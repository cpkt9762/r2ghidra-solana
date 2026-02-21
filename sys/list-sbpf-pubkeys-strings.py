#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import re
import struct
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Set, Tuple

BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
BASE58_MAP = {c: i for i, c in enumerate(BASE58_ALPHABET)}
BASE58_TOKEN_RE = re.compile(
    r"(?<![1-9A-HJ-NP-Za-km-z])[1-9A-HJ-NP-Za-km-z]{32,44}(?![1-9A-HJ-NP-Za-km-z])"
)

MOV_IMM_RE = re.compile(r"\bmov(?:64)?\s+r(\d+),\s+0x([0-9a-fA-F]+)\b")
MOV_REG_RE = re.compile(r"\bmov(?:64)?\s+r(\d+),\s+r(\d+)\b")
HOR64_RE = re.compile(r"\bhor64\s+r(\d+),\s+0x([0-9a-fA-F]+)\b")
STXQ_RE = re.compile(r"\bstxq\s+\[r10([+-])0x([0-9a-fA-F]+)\],\s+r(\d+)\b")

REGION_BOUNDS = {
    1: (0x100000000, 0x200000000),
    2: (0x200000000, 0x300000000),
    3: (0x300000000, 0x400000000),
    4: (0x400000000, 0x500000000),
}


@dataclass
class StoreEvent:
    idx: int
    offset: int
    value: int
    has_hor: bool


@dataclass
class RegState:
    value: int
    has_hor: bool
    last_set_idx: int


@dataclass
class AddressRange:
    start: int
    end: int
    name: str


@dataclass
class RodataPointerHit:
    rodata_section: str
    rodata_vaddr: int
    rodata_paddr: int
    pointer: int
    region: int
    target: str


def run_r2(binary: Path, command: str) -> str:
    proc = subprocess.run(
        [
            "r2",
            "-q",
            "-e",
            "scr.color=0",
            "-e",
            "bin.relocs.apply=true",
            "-c",
            command,
            str(binary),
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    if proc.returncode != 0:
        raise RuntimeError(
            f"r2 command failed: {command}\nstdout:\n{proc.stdout}\nstderr:\n{proc.stderr}"
        )
    return proc.stdout


def b58_encode(raw: bytes) -> str:
    if not raw:
        return "1"
    n = int.from_bytes(raw, "big")
    out = []
    while n > 0:
        n, rem = divmod(n, 58)
        out.append(BASE58_ALPHABET[rem])
    prefix = 0
    for b in raw:
        if b == 0:
            prefix += 1
        else:
            break
    return ("1" * prefix) + ("".join(reversed(out)) if out else "")


def b58_decode_32(s: str) -> Optional[bytes]:
    if not s:
        return None
    n = 0
    for ch in s:
        v = BASE58_MAP.get(ch)
        if v is None:
            return None
        n = n * 58 + v
    raw = n.to_bytes((n.bit_length() + 7) // 8, "big")
    prefix = 0
    for ch in s:
        if ch == "1":
            prefix += 1
        else:
            break
    raw = (b"\x00" * prefix) + raw
    if len(raw) > 32:
        return None
    raw = raw.rjust(32, b"\x00")
    if b58_encode(raw) != s:
        return None
    return raw


def extract_strings(binary: Path, full_scan: bool = False) -> List[str]:
    out = run_r2(binary, "izzj" if full_scan else "izj")
    try:
        data = json.loads(out)
    except json.JSONDecodeError as err:
        raise RuntimeError(f"failed to parse izj output: {err}") from err
    strings: List[str] = []
    for item in data:
        s = item.get("string")
        if isinstance(s, str):
            strings.append(s)
    return strings


def extract_sections(binary: Path) -> List[dict]:
    out = run_r2(binary, "iSj")
    try:
        data = json.loads(out)
    except json.JSONDecodeError as err:
        raise RuntimeError(f"failed to parse iSj output: {err}") from err
    if not isinstance(data, list):
        raise RuntimeError("unexpected iSj output, expected JSON list")
    return [item for item in data if isinstance(item, dict)]


def build_known_ranges(sections: List[dict]) -> Dict[int, List[AddressRange]]:
    ranges: Dict[int, List[AddressRange]] = {1: [], 2: [], 3: [], 4: []}
    for s in sections:
        name = str(s.get("name", ""))
        vaddr = s.get("vaddr")
        if not isinstance(vaddr, int):
            continue
        if vaddr < 0x100000000 or vaddr >= 0x500000000:
            continue
        size = s.get("size")
        vsize = s.get("vsize")
        span = 0
        if isinstance(vsize, int) and vsize > 0:
            span = vsize
        elif isinstance(size, int) and size > 0:
            span = size
        if span <= 0:
            continue
        region = vaddr >> 32
        if region not in ranges:
            continue
        ranges[region].append(AddressRange(start=vaddr, end=vaddr + span, name=name or "section"))

    for region in (1, 2, 3, 4):
        if not ranges[region]:
            lo, hi = REGION_BOUNDS[region]
            ranges[region].append(AddressRange(start=lo, end=hi, name=f"region{region}"))
    return ranges


def match_range(value: int, region: int, known_ranges: Dict[int, List[AddressRange]]) -> Optional[AddressRange]:
    for r in known_ranges.get(region, []):
        if r.start <= value < r.end:
            return r
    return None


def extract_rodata_pointers(binary: Path, sections: List[dict]) -> List[RodataPointerHit]:
    with binary.open("rb") as f:
        blob = f.read()

    known_ranges = build_known_ranges(sections)
    hits: List[RodataPointerHit] = []

    rodata_sections = [
        s
        for s in sections
        if str(s.get("name", "")).startswith(".rodata")
        and isinstance(s.get("paddr"), int)
        and isinstance(s.get("vaddr"), int)
        and isinstance(s.get("size"), int)
        and s.get("size", 0) > 0
    ]

    for sec in rodata_sections:
        sec_name = str(sec.get("name", ".rodata"))
        paddr = int(sec["paddr"])
        vaddr = int(sec["vaddr"])
        size = int(sec["size"])
        if paddr < 0 or size <= 0 or paddr + size > len(blob):
            continue
        sec_bytes = blob[paddr : paddr + size]

        # sBPF pointers are qword values; scan 8-byte aligned slots in rodata.
        for off in range(0, len(sec_bytes) - 7, 8):
            ptr = struct.unpack_from("<Q", sec_bytes, off)[0]
            region = ptr >> 32
            if region not in REGION_BOUNDS:
                continue
            lo, hi = REGION_BOUNDS[region]
            if not (lo <= ptr < hi):
                continue
            target_range = match_range(ptr, region, known_ranges)
            # Region 1/2/3 should land in known mapped ranges; region 4 is dynamic input.
            if target_range is None and region in (1, 2, 3):
                continue
            target_name = target_range.name if target_range else f"region{region}"
            hits.append(
                RodataPointerHit(
                    rodata_section=sec_name,
                    rodata_vaddr=vaddr + off,
                    rodata_paddr=paddr + off,
                    pointer=ptr,
                    region=region,
                    target=target_name,
                )
            )

    hits.sort(key=lambda h: (h.rodata_vaddr, h.pointer))
    return hits


def extract_pubkeys_from_strings(strings: Iterable[str]) -> Set[str]:
    pubkeys: Set[str] = set()
    for s in strings:
        for token in BASE58_TOKEN_RE.findall(s):
            if not any(ch.isdigit() for ch in token):
                continue
            if not any("A" <= ch <= "Z" for ch in token):
                continue
            if not any("a" <= ch <= "z" for ch in token):
                continue
            if b58_decode_32(token) is not None:
                pubkeys.add(token)
    return pubkeys


def parse_store_events(disasm_text: str) -> List[StoreEvent]:
    regvals: Dict[int, RegState] = {}
    stores: List[StoreEvent] = []
    idx = 0

    for line in disasm_text.splitlines():
        idx += 1
        lowered = line.lower()
        generic_write = re.search(r"\b([a-z0-9_.]+)\s+r(\d+),", lowered)
        if generic_write:
            mnemonic = generic_write.group(1)
            dst_reg = int(generic_write.group(2))
            if mnemonic not in {"mov", "mov64", "hor64"}:
                regvals.pop(dst_reg, None)

        m = MOV_IMM_RE.search(line)
        if m:
            reg = int(m.group(1))
            imm = int(m.group(2), 16)
            regvals[reg] = RegState(value=imm, has_hor=False, last_set_idx=idx)
            continue

        m = MOV_REG_RE.search(line)
        if m:
            dst = int(m.group(1))
            src = int(m.group(2))
            src_state = regvals.get(src)
            if src_state:
                regvals[dst] = RegState(
                    value=src_state.value, has_hor=src_state.has_hor, last_set_idx=idx
                )
            else:
                regvals.pop(dst, None)
            continue

        m = HOR64_RE.search(line)
        if m:
            reg = int(m.group(1))
            hi = int(m.group(2), 16)
            if reg in regvals:
                prev = regvals[reg]
                regvals[reg] = RegState(
                    value=(prev.value | (hi << 32)),
                    has_hor=True,
                    last_set_idx=idx,
                )
            continue

        m = STXQ_RE.search(line)
        if m:
            sign = -1 if m.group(1) == "-" else 1
            off = int(m.group(2), 16) * sign
            reg = int(m.group(3))
            state = regvals.get(reg)
            if state is not None and (idx - state.last_set_idx) <= 12:
                stores.append(
                    StoreEvent(
                        idx=idx,
                        offset=off,
                        value=state.value & 0xFFFFFFFFFFFFFFFF,
                        has_hor=state.has_hor,
                    )
                )
            continue

    return stores


def choose_nearest(events: List[StoreEvent], idx: int, window: int) -> Optional[StoreEvent]:
    best: Optional[StoreEvent] = None
    best_dist = window + 1
    for ev in events:
        d = abs(ev.idx - idx)
        if d <= window and d < best_dist:
            best = ev
            best_dist = d
    return best


def extract_pubkeys_from_immediates(disasm_text: str, window: int = 160) -> Set[str]:
    stores = parse_store_events(disasm_text)
    by_offset: Dict[int, List[StoreEvent]] = {}
    for ev in stores:
        by_offset.setdefault(ev.offset, []).append(ev)

    pubkeys: Set[str] = set()
    seen_groups: Set[Tuple[int, int, int, int, int]] = set()

    for ev in stores:
        base = ev.offset
        group: List[StoreEvent] = []
        ok = True
        for delta in (0, 8, 16, 24):
            candidates = by_offset.get(base + delta)
            if not candidates:
                ok = False
                break
            nearest = choose_nearest(candidates, ev.idx, window)
            if nearest is None:
                ok = False
                break
            group.append(nearest)
        if not ok:
            continue

        sig = tuple(sorted((g.idx, g.offset, g.value) for g in group))
        if sig in seen_groups:
            continue
        seen_groups.add(sig)

        if max(g.idx for g in group) - min(g.idx for g in group) > 40:
            continue
        if sum(1 for g in group if g.has_hor) < 3:
            continue
        if any(g.offset < 0 for g in group):
            continue

        raw = b"".join(g.value.to_bytes(8, "little", signed=False) for g in group)
        if raw == (b"\x00" * 32):
            continue
        pubkeys.add(b58_encode(raw))

    return pubkeys


def print_text(strings: List[str], pubkeys: List[str], rodata_pointers: List[RodataPointerHit]) -> None:
    print(f"PUBKEYS ({len(pubkeys)})")
    for i, p in enumerate(pubkeys):
        print(f"{i:03d} {p}")
    print("")
    print(f"RODATA_POINTERS ({len(rodata_pointers)})")
    for i, h in enumerate(rodata_pointers):
        print(
            f"{i:03d} ro_vaddr=0x{h.rodata_vaddr:016x} ro_paddr=0x{h.rodata_paddr:08x} "
            f"ptr=0x{h.pointer:016x} region={h.region} target={h.target}"
        )
    print("")
    print(f"STRINGS ({len(strings)})")
    for i, s in enumerate(strings):
        print(f"{i:03d} {s}")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="One-shot list of Solana pubkeys and strings from an sBPF .so binary."
    )
    parser.add_argument("binary", help="Path to .so binary")
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output JSON instead of text",
    )
    parser.add_argument(
        "--full-strings",
        action="store_true",
        help="Use izzj (whole binary strings). Default uses izj (data-section strings).",
    )
    parser.add_argument(
        "-o",
        "--output",
        help="Write output to file (stdout if omitted)",
    )
    args = parser.parse_args()

    binary = Path(args.binary).expanduser().resolve()
    if not binary.is_file():
        print(f"binary not found: {binary}", file=sys.stderr)
        return 2

    try:
        sections = extract_sections(binary)
        strings = extract_strings(binary, full_scan=args.full_strings)
        string_pubkeys = extract_pubkeys_from_strings(strings)
        disasm_text = run_r2(binary, "aaa;pdr @@f")
        imm_pubkeys = extract_pubkeys_from_immediates(disasm_text)
        rodata_pointers = extract_rodata_pointers(binary, sections)
    except Exception as err:
        print(f"error: {err}", file=sys.stderr)
        return 1

    pubkeys = sorted(string_pubkeys | imm_pubkeys)
    if args.json:
        payload = {
            "binary": str(binary),
            "pubkeys": pubkeys,
            "rodata_pointers": [
                {
                    "rodata_section": h.rodata_section,
                    "rodata_vaddr": h.rodata_vaddr,
                    "rodata_paddr": h.rodata_paddr,
                    "pointer": h.pointer,
                    "region": h.region,
                    "target": h.target,
                }
                for h in rodata_pointers
            ],
            "strings": strings,
        }
        out = json.dumps(payload, ensure_ascii=False, indent=2)
    else:
        from io import StringIO

        buf = StringIO()
        stdout = sys.stdout
        try:
            sys.stdout = buf
            print_text(strings, pubkeys, rodata_pointers)
        finally:
            sys.stdout = stdout
        out = buf.getvalue()

    if args.output:
        Path(args.output).expanduser().write_text(out, encoding="utf-8")
    else:
        print(out, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
