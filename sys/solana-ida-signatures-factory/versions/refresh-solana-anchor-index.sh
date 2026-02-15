#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT_DIR="${SCRIPT_DIR}"
TMP_DIR="${TMPDIR:-/tmp}/solana-anchor-index.$$"
MAX_RETRIES=6
RETRY_SLEEP=1
MISSING_FILE="${OUT_DIR}/missing-crates.txt"

mkdir -p "${TMP_DIR}"
trap 'rm -rf "${TMP_DIR}"' EXIT

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

extract_http_body() {
	awk 'BEGIN{body=0} body{print} /^\r?$/{body=1}'
}

http_get() {
	local url="$1"
	local out="$2"
	local attempt=1

	while [ "${attempt}" -le "${MAX_RETRIES}" ]; do
		if curl -sS -i "${url}" > "${out}.raw" 2>/dev/null; then
			local code
			code="$(awk 'NR==1 {print $2}' "${out}.raw")"
			if [[ "${code}" =~ ^2[0-9][0-9]$ ]]; then
				extract_http_body < "${out}.raw" > "${out}"
				return 0
			fi
			warn "HTTP ${code} for ${url} (attempt ${attempt}/${MAX_RETRIES})"
		else
			warn "curl failed for ${url} (attempt ${attempt}/${MAX_RETRIES})"
		fi
		attempt=$((attempt + 1))
		sleep "${RETRY_SLEEP}"
	done

	return 1
}

http_get_with_headers() {
	local url="$1"
	local hdr_out="$2"
	local body_out="$3"
	local attempt=1

	while [ "${attempt}" -le "${MAX_RETRIES}" ]; do
		if curl -sS -i "${url}" > "${body_out}.raw" 2>/dev/null; then
			local code
			code="$(awk 'NR==1 {print $2}' "${body_out}.raw")"
			if [[ "${code}" =~ ^2[0-9][0-9]$ ]]; then
				sed -n '1,/^\r$/p' "${body_out}.raw" | tr -d '\r' > "${hdr_out}"
				extract_http_body < "${body_out}.raw" > "${body_out}"
				return 0
			fi
			warn "HTTP ${code} for ${url} (attempt ${attempt}/${MAX_RETRIES})"
		else
			warn "curl failed for ${url} (attempt ${attempt}/${MAX_RETRIES})"
		fi
		attempt=$((attempt + 1))
		sleep "${RETRY_SLEEP}"
	done

	return 1
}

fetch_github_release_tags() {
	local repo="$1"
	local out_file="$2"
	local hdr="${TMP_DIR}/${repo//\//_}.hdr"
	local body="${TMP_DIR}/${repo//\//_}.body.json"
	local page_file="${TMP_DIR}/${repo//\//_}.tags.tmp"
	: > "${page_file}"

	http_get_with_headers "https://api.github.com/repos/${repo}/releases?per_page=100&page=1" "${hdr}" "${body}" || return 1
	jq -r '.[].tag_name' "${body}" >> "${page_file}"

	local last_page
	last_page="$(sed -n 's/.*[?&]page=\([0-9][0-9]*\)>; rel="last".*/\1/p' "${hdr}" | tail -n1)"
	if [ -z "${last_page}" ]; then
		last_page=1
	fi

	local page=2
	while [ "${page}" -le "${last_page}" ]; do
		http_get "https://api.github.com/repos/${repo}/releases?per_page=100&page=${page}" "${body}" || return 1
		jq -r '.[].tag_name' "${body}" >> "${page_file}"
		page=$((page + 1))
	done

	sort -u "${page_file}" > "${out_file}"
}

fetch_crate_versions() {
	local crate="$1"
	local out_file="$2"
	local body="${TMP_DIR}/crate-${crate}.json"

	if ! http_get "https://crates.io/api/v1/crates/${crate}/versions" "${body}"; then
		warn "skip crate ${crate}: unable to query crates.io"
		return 1
	fi

	jq -r '.versions[] | select(.yanked | not) | .num' "${body}" | sort -V -u > "${out_file}"
}

log "Fetching solana release tags from anza-xyz/agave and solana-labs/solana"
fetch_github_release_tags "anza-xyz/agave" "${TMP_DIR}/agave.tags" || die "failed to fetch anza-xyz/agave releases"
fetch_github_release_tags "solana-labs/solana" "${TMP_DIR}/solana.tags" || die "failed to fetch solana-labs/solana releases"

cat "${TMP_DIR}/agave.tags" "${TMP_DIR}/solana.tags" 2>/dev/null | \
	sed 's/^v//' | sed '/^$/d' | sort -V -u > "${OUT_DIR}/solana-release-tags.txt"

log "Fetching Solana crate universe from agave workspace dependencies"
AGAVE_CARGO="${TMP_DIR}/agave.Cargo.toml"
http_get "https://raw.githubusercontent.com/anza-xyz/agave/master/Cargo.toml" "${AGAVE_CARGO}"
awk '
	/^\[workspace.dependencies\]/ { in_dep=1; next }
	in_dep && /^\[/ { exit }
	in_dep && $1 ~ /^solana-[A-Za-z0-9_-]+$/ {
		gsub("=", "", $1)
		print $1
	}
' "${AGAVE_CARGO}" | sort -u > "${OUT_DIR}/solana-rust-crates.txt"

log "Building Anchor crate universe from anchor workspace + runtime deps"
ANCHOR_CARGO="${TMP_DIR}/anchor.Cargo.toml"
http_get "https://raw.githubusercontent.com/coral-xyz/anchor/master/Cargo.toml" "${ANCHOR_CARGO}"

cat > "${TMP_DIR}/anchor-seed.txt" <<'EOF'
anchor-lang
anchor-spl
anchor-client
anchor-cli
anchor-idl
anchor-lang-idl
anchor-lang-idl-spec
anchor-attribute-access-control
anchor-attribute-account
anchor-attribute-constant
anchor-attribute-error
anchor-attribute-event
anchor-attribute-program
anchor-derive-accounts
anchor-derive-serde
anchor-derive-space
anchor-syn
avm
EOF

for seed in anchor-lang anchor-spl; do
	seed_ver_file="${TMP_DIR}/${seed}.versions.txt"
	seed_dep_file="${TMP_DIR}/${seed}.deps.json"
	fetch_crate_versions "${seed}" "${seed_ver_file}" || true
	seed_latest="$(tail -n 1 "${seed_ver_file}" 2>/dev/null || true)"
	if [ -n "${seed_latest}" ]; then
		if http_get "https://crates.io/api/v1/crates/${seed}/${seed_latest}/dependencies" "${seed_dep_file}"; then
			jq -r '.dependencies[].crate_id | select(test("^anchor-"))' "${seed_dep_file}" >> "${TMP_DIR}/anchor-seed.txt"
		fi
	fi
done

sort -u "${TMP_DIR}/anchor-seed.txt" > "${OUT_DIR}/anchor-crates.txt"

log "Pruning stale per-crate version files"
find "${OUT_DIR}" -maxdepth 1 -type f -name '*.txt' \
	! -name 'solana-release-tags.txt' \
	! -name 'solana-rust-crates.txt' \
	! -name 'anchor-crates.txt' \
	! -name 'missing-crates.txt' \
	-delete

log "Fetching versions for Solana crates"
: > "${MISSING_FILE}"
while IFS= read -r crate; do
	[ -n "${crate}" ] || continue
	if ! fetch_crate_versions "${crate}" "${OUT_DIR}/${crate}.txt"; then
		printf '%s\n' "${crate}" >> "${MISSING_FILE}"
	fi
done < "${OUT_DIR}/solana-rust-crates.txt"

log "Fetching versions for Anchor crates"
while IFS= read -r crate; do
	[ -n "${crate}" ] || continue
	if ! fetch_crate_versions "${crate}" "${OUT_DIR}/${crate}.txt"; then
		printf '%s\n' "${crate}" >> "${MISSING_FILE}"
	fi
done < "${OUT_DIR}/anchor-crates.txt"

sort -u -o "${MISSING_FILE}" "${MISSING_FILE}"

log "Done."
log "Generated files:"
log "  ${OUT_DIR}/solana-release-tags.txt"
log "  ${OUT_DIR}/solana-rust-crates.txt"
log "  ${OUT_DIR}/anchor-crates.txt"
log "  ${OUT_DIR}/missing-crates.txt"
log "  ${OUT_DIR}/*.txt (per-crate versions)"
