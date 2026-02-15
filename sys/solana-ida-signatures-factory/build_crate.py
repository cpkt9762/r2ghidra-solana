import argparse
import os
import pathlib
import subprocess

try:
    from colorama import Fore, Style, init
except ImportError:
    class _NoColor:
        def __getattr__(self, _name):
            return ""

    Fore = _NoColor()
    Style = _NoColor()

    def init(*_args, **_kwargs):
        return None

init()

ROOT_DIR = pathlib.Path(__file__).resolve().parent
SOLANA_DIR = ROOT_DIR / "solana"
CRATES_DIR = ROOT_DIR / "crates"

LOCKFILE_V4_HINT = "lock file version 4 requires `-Znext-lockfile-bump`"
EDITION_2024_HINTS = (
    "feature `edition2024` is required",
    "older than the `2024` edition",
)
AHASH_HINT = "use of unstable library feature 'build_hasher_simple_hash_one'"

# blake3 v1.8.3 currently requires edition2024 and breaks old Cargo in Solana toolchains.
BLAKE3_LOCK_V183 = """name = "blake3"
version = "1.8.3"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "2468ef7d57b3fb7e16b576e8377cdbde2320c60e1491e961d11da40fc4f02a2d"
dependencies = [
 "arrayref",
 "arrayvec",
 "cc",
 "cfg-if",
 "constant_time_eq",
 "cpufeatures",
 "digest 0.10.7",
]
"""

BLAKE3_LOCK_V182 = """name = "blake3"
version = "1.8.2"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "3888aaa89e4b2a40fca9848e400f6a658a5a3978de7be858e209cafa8be9a4a0"
dependencies = [
 "arrayref",
 "arrayvec",
 "cc",
 "cfg-if",
 "constant_time_eq",
 "digest 0.10.7",
]
"""


def run_cmd(args, cwd=None, env=None):
    proc = subprocess.run(
        args,
        cwd=cwd,
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    return proc.returncode, proc.stdout


def ensure_solana_release(solana_version: str):
    solana_dir = SOLANA_DIR / f"solana-release-{solana_version}"
    if solana_dir.exists():
        return True
    print(f"{Fore.BLUE}Solana version {solana_version} not found, installing...{Style.RESET_ALL}")
    code, out = run_cmd(["bash", str(ROOT_DIR / "install-solana.sh"), solana_version], cwd=ROOT_DIR)
    if out:
        print(out)
    return code == 0 and solana_dir.exists()


def ensure_crate(crate: str, version: str):
    crate_dir = CRATES_DIR / f"{crate}-{version}"
    if crate_dir.exists():
        return True
    print(f"{Fore.BLUE}Crate {crate} version {version} not found, fetching...{Style.RESET_ALL}")
    code, out = run_cmd(["bash", str(ROOT_DIR / "fetch-crate.sh"), crate, version], cwd=ROOT_DIR)
    if out:
        print(out)
    return code == 0 and crate_dir.exists()


def apply_ahash_patch(crate_dir: pathlib.Path):
    cargo_toml = crate_dir / "Cargo.toml"
    marker = "ahash = \"=0.8.6\""
    txt = cargo_toml.read_text()
    if marker in txt:
        return False
    txt += "\n[dependencies]\nahash = \"=0.8.6\"\n"
    cargo_toml.write_text(txt)
    return True


def drop_lockfile(crate_dir: pathlib.Path):
    lock_file = crate_dir / "Cargo.lock"
    if not lock_file.exists():
        return False
    lock_file.unlink()
    return True


def patch_blake3_lock(crate_dir: pathlib.Path):
    lock_file = crate_dir / "Cargo.lock"
    if not lock_file.exists():
        return False
    txt = lock_file.read_text()
    if BLAKE3_LOCK_V183 not in txt:
        return False
    lock_file.write_text(txt.replace(BLAKE3_LOCK_V183, BLAKE3_LOCK_V182))
    return True


def run_build(crate_dir: pathlib.Path, cargo_build_sbf: pathlib.Path):
    rustc_env = os.environ.copy()
    rustc_env["RUSTFLAGS"] = "-C overflow-checks=on"
    return run_cmd([str(cargo_build_sbf)], cwd=crate_dir, env=rustc_env)


def build_crate(crate: str, version: str, solana_version: str, only_rlib=True):
    del only_rlib
    if not ensure_solana_release(solana_version):
        print(f"{Fore.RED}Failed to install solana version {solana_version}{Style.RESET_ALL}")
        return False, ""
    if not ensure_crate(crate, version):
        print(f"{Fore.RED}Failed to fetch crate {crate} version {version}{Style.RESET_ALL}")
        return False, ""

    solana_dir = SOLANA_DIR / f"solana-release-{solana_version}"
    crate_dir = CRATES_DIR / f"{crate}-{version}"
    cargo_build_sbf = (solana_dir / "bin" / "cargo-build-sbf").resolve()
    if not cargo_build_sbf.exists():
        print(f"{Fore.RED}cargo-build-sbf not found at {cargo_build_sbf}{Style.RESET_ALL}")
        return False, ""

    print(f"{Fore.BLUE}Building crate {crate} version {version} with toolchain {solana_version}...{Style.RESET_ALL}")
    patched_ahash = False
    patched_lock = False
    patched_blake3 = False
    last_status = ""

    for _attempt in range(1, 6):
        _code, status = run_build(crate_dir, cargo_build_sbf)
        last_status = status
        print(status)
        if "Finished release" in status:
            print(f"{Fore.GREEN}Crate {crate} version {version} built successfully!{Style.RESET_ALL}")
            return True, status

        if (not patched_ahash) and AHASH_HINT in status:
            print(f"{Fore.YELLOW}[compat] applying ahash pin...{Style.RESET_ALL}")
            patched_ahash = apply_ahash_patch(crate_dir)
            if patched_ahash:
                continue

        if (not patched_lock) and LOCKFILE_V4_HINT in status:
            print(f"{Fore.YELLOW}[compat] dropping Cargo.lock v4...{Style.RESET_ALL}")
            patched_lock = drop_lockfile(crate_dir)
            if patched_lock:
                continue

        if (not patched_blake3) and any(h in status for h in EDITION_2024_HINTS):
            print(f"{Fore.YELLOW}[compat] patching blake3 lock entry 1.8.3 -> 1.8.2...{Style.RESET_ALL}")
            patched_blake3 = patch_blake3_lock(crate_dir)
            if patched_blake3:
                continue

        break

    print(f"{Fore.RED}Crate {crate} version {version} build failed!{Style.RESET_ALL}")
    return False, last_status


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--solana-version", type=str, required=True, help="Compiler toolchain Solana version")
    parser.add_argument("crate", type=str, help="Crate name")
    parser.add_argument("version", type=str, help="Crate version")
    args = parser.parse_args()

    ok, _ = build_crate(args.crate, args.version, args.solana_version)
    raise SystemExit(0 if ok else 1)
