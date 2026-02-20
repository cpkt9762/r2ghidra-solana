#!/usr/bin/env bash

set -euo pipefail

usage() {
	cat <<'EOF'
Usage:
  build-sbpf-zigns-by-folder.sh [options]

Options:
  --release-dir <path>      Directory containing core/ crypto/ anchor/ trees
                            (default: ./solana-sbpf-rlib-release/v1.0.0)
  --groups <csv>            Comma-separated groups to process (default: core,crypto,anchor)
  --jobs <n>                Max parallel workers (default: 8)
  --work-root <path>        Working root (default: ./tmp-zigns-by-folder)
  --merged-out <path>       Output merged sdb
                            (default: ./sdb/solana-sbpf-rlib-by-folder-merged.sdb)
  --namespace-prefix <txt>  Namespace prefix (default: solana_sbpf_rlib_v1_0_0)
  --ar <path>               ar/llvm-ar path (default: auto)
  --r2 <path>               r2 path (default: r2)
  --force                   Rebuild parts even if per-folder .sdb exists
  -h, --help                Show this help
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

sanitize() {
	local s="$1"
	s="$(printf '%s' "$s" | sed -E 's/[^A-Za-z0-9_]+/_/g; s/_+/_/g; s/^_+//; s/_+$//')"
	[ -n "$s" ] || s="unnamed"
	printf '%s\n' "$s"
}

resolve_abs_path() {
	local p="$1"
	if [ -d "$p" ]; then
		( cd "$p" && pwd )
	else
		local d b
		d="$(dirname "$p")"
		b="$(basename "$p")"
		mkdir -p "$d"
		( cd "$d" && printf '%s/%s\n' "$(pwd)" "$b" )
	fi
}

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RELEASE_DIR="${SCRIPT_DIR}/solana-sbpf-rlib-release/v1.0.0"
GROUPS_CSV="core,crypto,anchor"
JOBS=8
WORK_ROOT="${SCRIPT_DIR}/tmp-zigns-by-folder"
MERGED_OUT="${SCRIPT_DIR}/sdb/solana-sbpf-rlib-by-folder-merged.sdb"
NAMESPACE_PREFIX="solana_sbpf_rlib_v1_0_0"
AR_BIN=""
R2_BIN="r2"
FORCE=0

while [ "$#" -gt 0 ]; do
	case "$1" in
	--release-dir)
		RELEASE_DIR="$2"
		shift 2
		;;
	--groups)
		GROUPS_CSV="$2"
		shift 2
		;;
	--jobs)
		JOBS="$2"
		shift 2
		;;
	--work-root)
		WORK_ROOT="$2"
		shift 2
		;;
	--merged-out)
		MERGED_OUT="$2"
		shift 2
		;;
	--namespace-prefix)
		NAMESPACE_PREFIX="$2"
		shift 2
		;;
	--ar)
		AR_BIN="$2"
		shift 2
		;;
	--r2)
		R2_BIN="$2"
		shift 2
		;;
	--force)
		FORCE=1
		shift
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

RELEASE_DIR="$(resolve_abs_path "$RELEASE_DIR")"
WORK_ROOT="$(resolve_abs_path "$WORK_ROOT")"
MERGED_OUT="$(resolve_abs_path "$MERGED_OUT")"

[ -d "$RELEASE_DIR" ] || die "release-dir not found: $RELEASE_DIR"
command -v "$R2_BIN" >/dev/null 2>&1 || die "r2 not found: $R2_BIN"
[ -x "${SCRIPT_DIR}/build-sbpf-zigns.sh" ] || die "missing helper: ${SCRIPT_DIR}/build-sbpf-zigns.sh"

if [ -n "$AR_BIN" ]; then
	command -v "$AR_BIN" >/dev/null 2>&1 || die "ar not found: $AR_BIN"
else
	if [ -x "/opt/homebrew/opt/llvm/bin/llvm-ar" ]; then
		AR_BIN="/opt/homebrew/opt/llvm/bin/llvm-ar"
	elif command -v llvm-ar >/dev/null 2>&1; then
		AR_BIN="$(command -v llvm-ar)"
	elif command -v ar >/dev/null 2>&1; then
		AR_BIN="$(command -v ar)"
	else
		die "cannot find llvm-ar/ar"
	fi
fi

mkdir -p "$WORK_ROOT/flat" "$WORK_ROOT/parts" "$WORK_ROOT/logs" "$WORK_ROOT/work" "$(dirname "$MERGED_OUT")"

manifest="$WORK_ROOT/manifest.tsv"
: > "$manifest"

IFS=',' read -r -a groups <<< "$GROUPS_CSV"
for group in "${groups[@]}"; do
	group="$(sanitize "$group")"
	src_group="${RELEASE_DIR}/${group}"
	[ -d "$src_group" ] || {
		warn "group dir missing, skip: $src_group"
		continue
	}
	while IFS= read -r folder; do
		name="$(basename "$folder")"
		pkg_id="${group}__$(sanitize "$name")"
		flat_dir="${WORK_ROOT}/flat/${pkg_id}"
		part_db="${WORK_ROOT}/parts/${pkg_id}.sdb"
		part_log="${WORK_ROOT}/logs/${pkg_id}.log"
		part_work="${WORK_ROOT}/work/${pkg_id}"
		printf '%s\t%s\t%s\t%s\t%s\n' "$pkg_id" "$folder" "$flat_dir" "$part_db" "$part_work" >> "$manifest"
	done < <(find "$src_group" -mindepth 1 -maxdepth 1 -type d | sort)
done

total_pkgs="$(wc -l < "$manifest" | tr -d ' ')"
[ "$total_pkgs" -gt 0 ] || die "no package folders found"
log "Package folders: $total_pkgs (groups: $GROUPS_CSV)"

while IFS=$'\t' read -r pkg_id folder flat_dir part_db _part_work; do
	if [ "$FORCE" -eq 0 ] && [ -s "$part_db" ]; then
		continue
	fi
	rm -rf "$flat_dir"
	mkdir -p "$flat_dir"
	count=0
	while IFS= read -r -d '' rlib; do
		rel="${rlib#$folder/}"
		key="${rel//\//__}"
		ln -f "$rlib" "${flat_dir}/${key}"
		count=$((count + 1))
	done < <(find "$folder" -type f -name '*.rlib' -print0)
	if [ "$count" -eq 0 ]; then
		warn "no rlib in $folder"
		continue
	fi
	log "Prepared $pkg_id ($count rlibs)"
done < "$manifest"

wait_slot() {
	while true; do
		active="$(jobs -pr | wc -l | tr -d ' ')"
		[ "$active" -lt "$JOBS" ] && break
		sleep 1
	done
}

declare -a pids=()
declare -a ids=()
built=0
skipped=0

while IFS=$'\t' read -r pkg_id _folder flat_dir part_db part_work; do
	part_log="${WORK_ROOT}/logs/${pkg_id}.log"
	if [ ! -d "$flat_dir" ]; then
		warn "skip $pkg_id (flat dir missing)"
		skipped=$((skipped + 1))
		continue
	fi
	if [ "$FORCE" -eq 0 ] && [ -s "$part_db" ]; then
		log "Skip existing part: $pkg_id"
		skipped=$((skipped + 1))
		continue
	fi
	wait_slot
	(
		"${SCRIPT_DIR}/build-sbpf-zigns.sh" \
			--out-db "$part_db" \
			--work-dir "$part_work" \
			--skip-fetch \
			--no-rust-core \
			--extra-rlib-dir "$flat_dir" \
			--namespace-prefix "${NAMESPACE_PREFIX}__${pkg_id}" \
			--ar "$AR_BIN" \
			--r2 "$R2_BIN" \
			> "$part_log" 2>&1
	) &
	pids+=("$!")
	ids+=("$pkg_id")
	built=$((built + 1))
	log "Launched $pkg_id (pid=$!)"
done < "$manifest"

fail=0
for i in "${!pids[@]}"; do
	if wait "${pids[$i]}"; then
		log "Done ${ids[$i]}"
	else
		warn "Failed ${ids[$i]} (log: ${WORK_ROOT}/logs/${ids[$i]}.log)"
		fail=$((fail + 1))
	fi
done

log "Build finished: launched=$built skipped=$skipped failed=$fail"

rm -f "$MERGED_OUT"
merged_parts=0
while IFS= read -r part_db; do
	[ -s "$part_db" ] || continue
	"$R2_BIN" -2 -q -e scr.color=false \
		-c "zo ${part_db};zos ${MERGED_OUT};q" /bin/ls >/dev/null 2>&1 || {
		warn "merge failed for $part_db"
		continue
	}
	merged_parts=$((merged_parts + 1))
done < <(find "$WORK_ROOT/parts" -maxdepth 1 -type f -name '*.sdb' | sort)

[ -f "$MERGED_OUT" ] || die "merge output missing: $MERGED_OUT"
size="$(wc -c < "$MERGED_OUT" | tr -d ' ')"
log "Merged parts: $merged_parts -> $MERGED_OUT (${size} bytes)"

if [ "$fail" -gt 0 ]; then
	exit 1
fi
