#!/usr/bin/env bash

set -eo pipefail

usage() {
	cat <<'EOF'
Usage:
  build-sbpf-zigns.sh --out-db <file.sdb> [options]

Options:
  --out-db <path>              Output zignature sdb file (required)
  --work-dir <path>            Working directory (default: /tmp/r2ghidra-sbpf-zigns)
  --factory-dir <path>         solana-ida-signatures-factory path
                               (default: $HOME/Documents/jup/solana-ida-signatures-factory)
  --solana-version <version>   Solana version used by factory when fetching crates
                               (default: 1.18.26)
  --sbpf-target <triple>       Rust sbpf target for rustlib scan
                               (default: sbpfv3-solana-solana)
  --rustlib-dir <path>         Override rustlib directory
                               (example: ~/.cache/solana/v1.48/platform-tools/rust/lib/rustlib/sbpfv3-solana-solana/lib)
  --crate <name:version>       Crate + version to fetch via factory (repeatable)
                               (example: --crate solana-program:1.18.16)
  --crate-file <name:path>     Crate + versions file to fetch via factory (repeatable)
                               (example: --crate-file anchor-lang:versions/anchor-lang.txt)
  --extra-rlib-dir <path>      Add prebuilt .rlib directory (repeatable)
  --extra-obj-dir <path>       Add .o directory directly (repeatable)
  --skip-fetch                 Do not run factory fetch/build scripts
  --no-rust-core               Skip rust core-set (core/alloc/compiler_builtins/std)
  --r2 <path>                  r2 binary (default: r2)
  --ar <path>                  llvm-ar/ar binary (auto-detect by default)
  --minsz <n>                  zign.minsz (default: 16)
  --mincc <n>                  zign.mincc (default: 10)
  -h, --help                   Show this help

Notes:
  - This script merges zigns incrementally into --out-db with `zos`.
  - For large corpora, run with --skip-fetch and pre-populated rlibs to avoid repeated builds.
EOF
}

log() {
	printf '[*] %s\n' "$*"
}

warn() {
	printf '[!] %s\n' "$*" >&2
}

die() {
	printf '[x] %s\n' "$*" >&2
	exit 1
}

resolve_abs_path() {
	local p="$1"
	if [ -d "$p" ]; then
		( cd "$p" && pwd )
	else
		local d
		d="$(dirname "$p")"
		local b
		b="$(basename "$p")"
		mkdir -p "$d"
		( cd "$d" && printf '%s/%s\n' "$(pwd)" "$b" )
	fi
}

normalize_spec() {
	local spec="$1"
	if [[ "$spec" == *:* ]]; then
		printf '%s\n' "$spec"
	elif [[ "$spec" == *=* ]]; then
		printf '%s\n' "${spec/=/:}"
	else
		die "Invalid spec '$spec' (expected name:arg)"
	fi
}

OUT_DB=""
WORK_DIR="${TMPDIR:-/tmp}/r2ghidra-sbpf-zigns"
FACTORY_DIR="${HOME}/Documents/jup/solana-ida-signatures-factory"
SOLANA_VERSION="1.18.26"
SBPF_TARGET="sbpfv3-solana-solana"
RUSTLIB_DIR=""
FETCH_CRATES=1
USE_RUST_CORE=1
R2_BIN="r2"
AR_BIN=""
MINSZ=16
MINCC=10

declare -a CRATE_SPECS=()
declare -a CRATE_FILE_SPECS=()
declare -a EXTRA_RLIB_DIRS=()
declare -a EXTRA_OBJ_DIRS=()

while [ "$#" -gt 0 ]; do
	case "$1" in
	--out-db)
		OUT_DB="$2"
		shift 2
		;;
	--work-dir)
		WORK_DIR="$2"
		shift 2
		;;
	--factory-dir)
		FACTORY_DIR="$2"
		shift 2
		;;
	--solana-version)
		SOLANA_VERSION="$2"
		shift 2
		;;
	--sbpf-target)
		SBPF_TARGET="$2"
		shift 2
		;;
	--rustlib-dir)
		RUSTLIB_DIR="$2"
		shift 2
		;;
	--crate)
		CRATE_SPECS+=("$(normalize_spec "$2")")
		shift 2
		;;
	--crate-file)
		CRATE_FILE_SPECS+=("$(normalize_spec "$2")")
		shift 2
		;;
	--extra-rlib-dir)
		EXTRA_RLIB_DIRS+=("$2")
		shift 2
		;;
	--extra-obj-dir)
		EXTRA_OBJ_DIRS+=("$2")
		shift 2
		;;
	--skip-fetch)
		FETCH_CRATES=0
		shift
		;;
	--no-rust-core)
		USE_RUST_CORE=0
		shift
		;;
	--r2)
		R2_BIN="$2"
		shift 2
		;;
	--ar)
		AR_BIN="$2"
		shift 2
		;;
	--minsz)
		MINSZ="$2"
		shift 2
		;;
	--mincc)
		MINCC="$2"
		shift 2
		;;
	-h|--help)
		usage
		exit 0
		;;
	*)
		die "Unknown argument: $1"
		;;
	esac
done

[ -n "$OUT_DB" ] || die "--out-db is required"

if [ -n "$AR_BIN" ]; then
	command -v "$AR_BIN" >/dev/null 2>&1 || die "ar binary not found: $AR_BIN"
else
	if command -v llvm-ar >/dev/null 2>&1; then
		AR_BIN="$(command -v llvm-ar)"
	elif command -v ar >/dev/null 2>&1; then
		AR_BIN="$(command -v ar)"
	else
		die "Neither llvm-ar nor ar found in PATH"
	fi
fi

if [[ "$R2_BIN" == */* ]]; then
	[ -x "$R2_BIN" ] || die "r2 binary not executable: $R2_BIN"
else
	command -v "$R2_BIN" >/dev/null 2>&1 || die "r2 binary not found: $R2_BIN"
fi

if [ "$FETCH_CRATES" -eq 1 ]; then
	[ -d "$FACTORY_DIR" ] || die "Factory directory not found: $FACTORY_DIR"
	[ -f "$FACTORY_DIR/get-rlibs-from-crate.py" ] || die "Missing factory script: $FACTORY_DIR/get-rlibs-from-crate.py"
	command -v python3 >/dev/null 2>&1 || die "python3 not found (required for crate fetch)"
fi

WORK_DIR="$(resolve_abs_path "$WORK_DIR")"
OUT_DB="$(resolve_abs_path "$OUT_DB")"
mkdir -p "$WORK_DIR/rlibs" "$WORK_DIR/objs"

collect_factory_rlibs_for_crate() {
	local crate="$1"
	local src_dir="$FACTORY_DIR/rlibs/$crate"
	if [ ! -d "$src_dir" ]; then
		warn "No factory rlibs found for crate '$crate' under $src_dir"
		return 0
	fi
	local found=0
	local f
	shopt -s nullglob
	for f in "$src_dir"/*.rlib; do
		cp -f "$f" "$WORK_DIR/rlibs/"
		found=$((found + 1))
	done
	shopt -u nullglob
	log "Collected ${found} rlibs for crate '$crate'"
}

if [ "$FETCH_CRATES" -eq 1 ]; then
	if [ "${#CRATE_SPECS[@]}" -gt 0 ] || [ "${#CRATE_FILE_SPECS[@]}" -gt 0 ]; then
		log "Fetching/building crate rlibs via factory ($FACTORY_DIR)"
	fi
	for spec in "${CRATE_SPECS[@]}"; do
		crate="${spec%%:*}"
		version_list="${spec#*:}"
		IFS=',' read -r -a versions <<< "$version_list"
		for version in "${versions[@]}"; do
			log "Factory fetch crate=$crate version=$version solana=$SOLANA_VERSION"
			(
				cd "$FACTORY_DIR"
				python3 get-rlibs-from-crate.py --solana-version "$SOLANA_VERSION" --crate "$crate" --version "$version"
			)
		done
		collect_factory_rlibs_for_crate "$crate"
	done
	for spec in "${CRATE_FILE_SPECS[@]}"; do
		crate="${spec%%:*}"
		versions_file="${spec#*:}"
		log "Factory fetch crate=$crate versions-file=$versions_file solana=$SOLANA_VERSION"
		(
			cd "$FACTORY_DIR"
			python3 get-rlibs-from-crate.py --solana-version "$SOLANA_VERSION" --crate "$crate" --versions-file "$versions_file"
		)
		collect_factory_rlibs_for_crate "$crate"
	done
else
	log "Skipping factory fetch/build as requested"
fi

for dir in "${EXTRA_RLIB_DIRS[@]}"; do
	[ -d "$dir" ] || die "extra rlib dir not found: $dir"
	local_count=0
	while IFS= read -r -d '' file; do
		cp -f "$file" "$WORK_DIR/rlibs/"
		local_count=$((local_count + 1))
	done < <(find "$dir" -maxdepth 1 -type f -name '*.rlib' -print0)
	log "Collected ${local_count} rlibs from extra dir: $dir"
done

detect_rustlib_dir() {
	local target="$1"
	local candidates=()
	local c
	while IFS= read -r c; do
		candidates+=("$c")
	done < <(find "$HOME/.cache/solana" -type d -path "*/platform-tools/rust/lib/rustlib/${target}/lib" 2>/dev/null | sort -V)

	if [ "${#candidates[@]}" -eq 0 ] && [ "$target" = "sbpfv3-solana-solana" ]; then
		while IFS= read -r c; do
			candidates+=("$c")
		done < <(find "$HOME/.cache/solana" -type d -path "*/platform-tools/rust/lib/rustlib/sbf-solana-solana/lib" 2>/dev/null | sort -V)
	fi

	if [ "${#candidates[@]}" -eq 0 ]; then
		die "Unable to auto-detect rustlib dir for target '$target'. Use --rustlib-dir."
	fi
	printf '%s\n' "${candidates[$((${#candidates[@]} - 1))]}"
}

if [ "$USE_RUST_CORE" -eq 1 ]; then
	if [ -z "$RUSTLIB_DIR" ]; then
		RUSTLIB_DIR="$(detect_rustlib_dir "$SBPF_TARGET")"
	fi
	[ -d "$RUSTLIB_DIR" ] || die "rustlib dir not found: $RUSTLIB_DIR"
	log "Using rustlib dir: $RUSTLIB_DIR"

	rust_core_libs=(core alloc compiler_builtins std)
	for base in "${rust_core_libs[@]}"; do
		found=0
		shopt -s nullglob
		for f in "$RUSTLIB_DIR/lib${base}-"*.rlib; do
			cp -f "$f" "$WORK_DIR/rlibs/"
			found=$((found + 1))
		done
		shopt -u nullglob
		if [ "$found" -eq 0 ]; then
			warn "No rustlib found for $base under $RUSTLIB_DIR"
		else
			log "Collected ${found} rustlib(s): ${base}"
		fi
	done
fi

RLIB_LIST="$WORK_DIR/rlib-files.txt"
OBJ_LIST="$WORK_DIR/object-files.txt"
FAIL_LIST="$WORK_DIR/failed-objects.txt"
: > "$RLIB_LIST"
: > "$OBJ_LIST"
: > "$FAIL_LIST"

while IFS= read -r -d '' f; do
	printf '%s\n' "$f" >> "$RLIB_LIST"
done < <(find "$WORK_DIR/rlibs" -maxdepth 1 -type f -name '*.rlib' -print0 | sort -z)

if [ ! -s "$RLIB_LIST" ] && [ "${#EXTRA_OBJ_DIRS[@]}" -eq 0 ]; then
	die "No .rlib input found. Provide --crate/--crate-file/--extra-rlib-dir or disable --skip-fetch."
fi

if [ -s "$RLIB_LIST" ]; then
	while IFS= read -r rlib; do
		rlib_base="$(basename "$rlib" .rlib)"
		extract_dir="$WORK_DIR/objs/$rlib_base"
		rm -rf "$extract_dir"
		mkdir -p "$extract_dir"
		(
			cd "$extract_dir"
			"$AR_BIN" x "$rlib"
		)
		count=0
		while IFS= read -r -d '' obj; do
			printf '%s\n' "$obj" >> "$OBJ_LIST"
			count=$((count + 1))
		done < <(find "$extract_dir" -type f -name '*.o' -print0)
		log "Extracted ${count} object(s) from $(basename "$rlib")"
	done < "$RLIB_LIST"
fi

for dir in "${EXTRA_OBJ_DIRS[@]}"; do
	[ -d "$dir" ] || die "extra obj dir not found: $dir"
	count=0
	while IFS= read -r -d '' obj; do
		printf '%s\n' "$obj" >> "$OBJ_LIST"
		count=$((count + 1))
	done < <(find "$dir" -type f -name '*.o' -print0)
	log "Collected ${count} object(s) from extra obj dir: $dir"
done

if [ ! -s "$OBJ_LIST" ]; then
	die "No object files found to process"
fi

rm -f "$OUT_DB"
log "Generating zignature db: $OUT_DB"

total_objs="$(wc -l < "$OBJ_LIST" | tr -d ' ')"
done_objs=0
failed_objs=0

while IFS= read -r obj; do
	done_objs=$((done_objs + 1))
	if "$R2_BIN" -2 -q \
		-e "zign.mangled=true" \
		-e "zign.minsz=$MINSZ" \
		-e "zign.mincc=$MINCC" \
		-c "aa;zaM;zos $OUT_DB;q" \
		"$obj" >/dev/null 2>&1; then
		:
	else
		warn "r2 failed on object: $obj"
		printf '%s\n' "$obj" >> "$FAIL_LIST"
		failed_objs=$((failed_objs + 1))
	fi
	if [ $((done_objs % 100)) -eq 0 ]; then
		log "Progress: ${done_objs}/${total_objs} objects"
	fi
done < "$OBJ_LIST"

[ -f "$OUT_DB" ] || die "Output db not produced: $OUT_DB"
db_size="$(wc -c < "$OUT_DB" | tr -d ' ')"

log "Done. processed=${done_objs} failed=${failed_objs} db_size=${db_size} bytes"
log "Object list: $OBJ_LIST"
if [ -s "$FAIL_LIST" ]; then
	warn "Failed object list: $FAIL_LIST"
fi
