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
  --solana-version <version>   Solana release version for factory policy (required with fetch)
  --compiler-solana-version <v>
                               Primary Solana compiler version for factory builds (required with fetch)
  --fallback-compiler-solana-version <v>
                               Fallback compiler version for compatibility retry (required with fetch)
  --platform-tools-version <v>
                               Platform-tools version passed to cargo-build-sbf --tools-version (required with fetch)
  --sbpf-target <triple>       Rust sbpf target for rustlib scan
                               (default: sbf-solana-solana)
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
  --namespace-prefix <text>    Prefix used for generated zign names
                               (default: solana)
  -h, --help                   Show this help

Notes:
  - This script merges zigns incrementally into --out-db with `zos`.
  - Function names are normalized to: <namespace>__<sanitized_name>__h<hash>.
    This prevents invalid sdb keys and cross-version name collisions.
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

sanitize_token() {
	local s="$1"
	s="$(printf '%s' "$s" | sed -E 's/[^A-Za-z0-9_]+/_/g; s/_+/_/g; s/^_+//; s/_+$//')"
	if [ -z "$s" ]; then
		s="unnamed"
	fi
	printf '%s' "$s"
}

short_hash() {
	local input="$1"
	case "$HASH_TOOL" in
	shasum)
		printf '%s' "$input" | shasum -a 256 | awk '{print substr($1, 1, 12)}'
		;;
	sha256sum)
		printf '%s' "$input" | sha256sum | awk '{print substr($1, 1, 12)}'
		;;
	cksum)
		printf '%s' "$input" | cksum | awk '{print $1}'
		;;
	*)
		die "No supported hash tool available"
		;;
	esac
}

build_object_namespace() {
	local obj="$1"
	local module_tag
	local prefix="${WORK_DIR}/objs/"
	local rel="$obj"
	if [[ "$obj" == "$prefix"* ]]; then
		rel="${obj#$prefix}"
		module_tag="${rel%%/*}"
	else
		module_tag="$(basename "$(dirname "$obj")")"
	fi
	local ns_prefix
	local ns_sv
	local ns_target
	local ns_module
	ns_prefix="$(sanitize_token "$NAMESPACE_PREFIX")"
	ns_sv="$(sanitize_token "${COMPILER_SOLANA_VERSION:-unknown}")"
	ns_target="$(sanitize_token "${SBPF_TARGET:-unknown}")"
	ns_module="$(sanitize_token "${module_tag}")"
	printf '%s__sv_%s__t_%s__m_%s' "$ns_prefix" "$ns_sv" "$ns_target" "$ns_module"
}

build_r2_zaf_script() {
	local obj="$1"
	local script_path="$2"
	local ns="$3"
	local count=0

	{
		echo "aa"
		while IFS=' ' read -r off name; do
			[ -n "$off" ] || continue
			[ -n "$name" ] || continue
			local base_name
			base_name="$(sanitize_token "$name")"
			local digest
			digest="$(short_hash "${obj}|${off}|${name}")"
			local suffix="__h${digest}"
			local max_base_len=$((NAME_MAX_LEN - ${#ns} - ${#suffix} - 2))
			if [ "$max_base_len" -lt 8 ]; then
				max_base_len=8
			fi
			base_name="${base_name:0:max_base_len}"
			local zigname="${ns}__${base_name}${suffix}"
			printf 'zaf %s %s\n' "$name" "$zigname"
			count=$((count + 1))
		done < <("$R2_BIN" -2 -q -e scr.color=false -c "aa;afl;q" "$obj" 2>/dev/null | awk '/^0x/ {print $1 " " $NF}')
		printf 'zos %s\n' "$OUT_DB"
		echo "q"
	} > "$script_path"

	[ "$count" -gt 0 ]
}

OUT_DB=""
WORK_DIR="${TMPDIR:-/tmp}/r2ghidra-sbpf-zigns"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FACTORY_DIR="${SCRIPT_DIR}/solana-ida-signatures-factory"
SOLANA_VERSION=""
COMPILER_SOLANA_VERSION=""
FALLBACK_COMPILER_SOLANA_VERSION=""
PLATFORM_TOOLS_VERSION=""
SBPF_TARGET="sbf-solana-solana"
RUSTLIB_DIR=""
FETCH_CRATES=1
USE_RUST_CORE=1
R2_BIN="r2"
AR_BIN=""
HASH_TOOL=""
MINSZ=16
MINCC=10
NAMESPACE_PREFIX="solana"
NAME_MAX_LEN=120

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
	--compiler-solana-version)
		COMPILER_SOLANA_VERSION="$2"
		shift 2
		;;
	--fallback-compiler-solana-version)
		FALLBACK_COMPILER_SOLANA_VERSION="$2"
		shift 2
		;;
	--platform-tools-version)
		PLATFORM_TOOLS_VERSION="$2"
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
	--namespace-prefix)
		NAMESPACE_PREFIX="$2"
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

if command -v shasum >/dev/null 2>&1; then
	HASH_TOOL="shasum"
elif command -v sha256sum >/dev/null 2>&1; then
	HASH_TOOL="sha256sum"
elif command -v cksum >/dev/null 2>&1; then
	HASH_TOOL="cksum"
else
	die "No hash tool found (need shasum, sha256sum or cksum)"
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
	if [ "${#CRATE_SPECS[@]}" -gt 0 ] || [ "${#CRATE_FILE_SPECS[@]}" -gt 0 ]; then
		[ -n "$SOLANA_VERSION" ] || die "--solana-version is required when fetching crates"
		[ -n "$COMPILER_SOLANA_VERSION" ] || die "--compiler-solana-version is required when fetching crates"
		[ -n "$FALLBACK_COMPILER_SOLANA_VERSION" ] || die "--fallback-compiler-solana-version is required when fetching crates"
		[ -n "$PLATFORM_TOOLS_VERSION" ] || die "--platform-tools-version is required when fetching crates"
	fi
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
			log "Factory fetch crate=$crate version=$version solana=$SOLANA_VERSION compiler=$COMPILER_SOLANA_VERSION tools=$PLATFORM_TOOLS_VERSION"
			(
				cd "$FACTORY_DIR"
				python3 get-rlibs-from-crate.py \
					--solana-version "$SOLANA_VERSION" \
					--compiler-solana-version "$COMPILER_SOLANA_VERSION" \
					--fallback-compiler-solana-version "$FALLBACK_COMPILER_SOLANA_VERSION" \
					--platform-tools-version "$PLATFORM_TOOLS_VERSION" \
					--crate "$crate" \
					--version "$version"
			)
		done
		collect_factory_rlibs_for_crate "$crate"
	done
	for spec in "${CRATE_FILE_SPECS[@]}"; do
		crate="${spec%%:*}"
		versions_file="${spec#*:}"
		log "Factory fetch crate=$crate versions-file=$versions_file solana=$SOLANA_VERSION compiler=$COMPILER_SOLANA_VERSION tools=$PLATFORM_TOOLS_VERSION"
		(
			cd "$FACTORY_DIR"
			python3 get-rlibs-from-crate.py \
				--solana-version "$SOLANA_VERSION" \
				--compiler-solana-version "$COMPILER_SOLANA_VERSION" \
				--fallback-compiler-solana-version "$FALLBACK_COMPILER_SOLANA_VERSION" \
				--platform-tools-version "$PLATFORM_TOOLS_VERSION" \
				--crate "$crate" \
				--versions-file "$versions_file"
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

	# 1) If --platform-tools-version is set, try exact match first
	if [ -n "$PLATFORM_TOOLS_VERSION" ]; then
		local exact_dir="$HOME/.cache/solana/${PLATFORM_TOOLS_VERSION}/platform-tools/rust/lib/rustlib/${target}/lib"
		if [ -d "$exact_dir" ]; then
			printf '%s\n' "$exact_dir"
			return
		fi
		# sbf-solana-solana fallback for exact version
		if [ "$target" = "sbpfv3-solana-solana" ]; then
			exact_dir="$HOME/.cache/solana/${PLATFORM_TOOLS_VERSION}/platform-tools/rust/lib/rustlib/sbf-solana-solana/lib"
			if [ -d "$exact_dir" ]; then
				warn "Using sbf-solana-solana rustlib (sbpfv3 not found for tools ${PLATFORM_TOOLS_VERSION})"
				printf '%s\n' "$exact_dir"
				return
			fi
		fi
		warn "No rustlib found for tools version ${PLATFORM_TOOLS_VERSION}, falling back to global search"
	fi

	# 2) Global search fallback (pick latest by sort -V)
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

if [ "$USE_RUST_CORE" -eq 1 ] && [ -z "$RUSTLIB_DIR" ] && [ "$FETCH_CRATES" -eq 0 ] && [ -n "$PLATFORM_TOOLS_VERSION" ]; then
	expected_cache="$HOME/.cache/solana/${PLATFORM_TOOLS_VERSION}/platform-tools"
	if [ ! -d "$expected_cache" ]; then
		die "platform-tools ${PLATFORM_TOOLS_VERSION} not cached at ${expected_cache}.
  With --skip-fetch, cargo-build-sbf never runs, so platform-tools are not auto-downloaded.
  Fix: either run 'cargo-build-sbf --tools-version ${PLATFORM_TOOLS_VERSION}' once to populate the cache,
       or pass --rustlib-dir explicitly, or remove --skip-fetch."
	fi
fi

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
R2_CMD_DIR="$WORK_DIR/r2cmds"
: > "$RLIB_LIST"
: > "$OBJ_LIST"
: > "$FAIL_LIST"
mkdir -p "$R2_CMD_DIR"

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
	cmd_script="$R2_CMD_DIR/$(printf '%08d' "$done_objs").r2"
	obj_ns="$(build_object_namespace "$obj")"
	if build_r2_zaf_script "$obj" "$cmd_script" "$obj_ns"; then
		if "$R2_BIN" -2 -q \
			-e "zign.minsz=$MINSZ" \
			-e "zign.mincc=$MINCC" \
			-i "$cmd_script" \
			"$obj" >/dev/null 2>&1; then
			:
		else
			warn "r2 failed on object (namespaced mode): $obj"
			printf '%s\n' "$obj" >> "$FAIL_LIST"
			failed_objs=$((failed_objs + 1))
		fi
	else
		warn "Unable to derive function list for object, falling back: $obj"
		if "$R2_BIN" -2 -q \
			-e "zign.mangled=true" \
			-e "zign.minsz=$MINSZ" \
			-e "zign.mincc=$MINCC" \
			-c "aa;zaM;zos $OUT_DB;q" \
			"$obj" >/dev/null 2>&1; then
			:
		else
			warn "r2 failed on object (fallback mode): $obj"
			printf '%s\n' "$obj" >> "$FAIL_LIST"
			failed_objs=$((failed_objs + 1))
		fi
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
