#!/bin/bash
#
# Download a borrowed ereolen.dk / bibliotek.kk.dk book and decrypt it into
# a plain EPUB.
#
# The reader at bibliotek.kk.dk (and similar DPL-React based library sites) loads
# its viewer JS from https://reader.pubhub.dk/2.2.0/js/app.js. That viewer talks
# to https://bookstreaming.pubhub.dk:
#
#   GET /v1/order/metadata/<orderid>   -> JSON {title, author, key, ...}
#   GET /v1/order/file/<orderid>       -> 302 to a signed encrypted-ebooks-cdn URL
#
# `key` is a base64 string. The wrapped key is decrypted with AES-256-CBC using
# a key-encryption-key (KEK) hardcoded in app.js, with a zero IV. The viewer
# then has a quirk in its base64 decoder (Uint16Array on a half-sized buffer),
# so only the first 16 bytes of the wrapped ciphertext are actually fed to the
# AES routine — yielding a 16-byte AES-128 content-encryption-key (CEK).
#
# The encrypted EPUB file is AES-128-CTR encrypted with that CEK and a zero
# initial counter, with no additional padding or framing.
#
# shellcheck disable=SC2155

set -euo pipefail

function usage() {
  cat <<EOF
${0} <ORDERID-OR-READER-URL> [OUTPUT-FILE]

Download an ebook borrowed via a DPL-React based library reader (e.g.
bibliotek.kk.dk) and decrypt it into a plain EPUB.

Argument may be either a bare order-id UUID, or any URL containing one in an
\`orderid\` query parameter (the URL shown in the browser when reading works).

Output file defaults to "\${AUTHOR} - \${TITLE}.epub" in the current directory.

Environment variables:
  OPF_AUTHOR    override author in output filename
  OPF_TITLE     override title in output filename
  TMP           working directory (default: /tmp/makeebook)

Example:
  ${0} 'https://bibliotek.kk.dk/reader?orderid=00000000-0000-0000-0000-000000000000'
  ${0} 00000000-0000-0000-0000-000000000000
EOF
  exit 0
}

if [[ $# -lt 1 || $# -gt 2 ]]; then
  usage
fi

# Hardcoded KEK from reader.pubhub.dk/2.2.0/js/app.js (Constants.keyEncryptionKey).
# AES-256, IV is 16 zero bytes.
KEK_HEX='1ec1964520f7235f5cffc19f792897b3279f4b6e20cdd23a51379e2108956c4a'
ZERO_IV='00000000000000000000000000000000'
METADATA_URL='https://bookstreaming.pubhub.dk/v1/order/metadata'
FILE_URL='https://bookstreaming.pubhub.dk/v1/order/file'

INPUT="${1}"
OUTPUT_OVERRIDE="${2:-}"
TMP="${TMP:-/tmp/makeebook}"

UUID_RE='[[:xdigit:]]{8}-[[:xdigit:]]{4}-[[:xdigit:]]{4}-[[:xdigit:]]{4}-[[:xdigit:]]{12}'
if [[ "${INPUT}" =~ ${UUID_RE} ]]; then
  ORDER_ID="${BASH_REMATCH[0]}"
else
  echo "Could not find an order-id UUID in argument: ${INPUT}" >&2
  exit 1
fi

WORK_DIR="${TMP}/${ORDER_ID}"
mkdir -p "${WORK_DIR}"

echo "Order id:   ${ORDER_ID}" >&2
echo "Working in: ${WORK_DIR}" >&2

# 1. Fetch metadata.
METADATA_FILE="${WORK_DIR}/metadata.json"
curl --fail -sL "${METADATA_URL}/${ORDER_ID}" -o "${METADATA_FILE}"

TITLE=$(jq -r '.title // empty' "${METADATA_FILE}")
AUTHOR=$(jq -r '.author // empty' "${METADATA_FILE}")
WRAPPED_KEY_B64=$(jq -r '.key // empty' "${METADATA_FILE}")
CONTENT_ID=$(jq -r '.contentId // empty' "${METADATA_FILE}")

if [[ -z "${WRAPPED_KEY_B64}" ]]; then
  echo "Metadata response did not contain an encryption key:" >&2
  cat "${METADATA_FILE}" >&2
  exit 1
fi

TITLE="${OPF_TITLE:-${TITLE}}"
AUTHOR="${OPF_AUTHOR:-${AUTHOR}}"
echo "Title:      ${TITLE}" >&2
echo "Author:     ${AUTHOR}" >&2
echo "Content id: ${CONTENT_ID}" >&2

# 2. Recover the per-book content key.
#
# The wrapped key is 32 base64-decoded bytes, but reader.pubhub.dk's
# Base64Binary.decode() funnels them through `new Uint16Array(new ArrayBuffer(t))`,
# which has half as many slots as bytes — so only the first 16 bytes ever reach
# the AES code. Mirror that here: take one block, AES-256-CBC decrypt it with
# the KEK and a zero IV (no padding), result is the 16-byte AES-128 CEK.
WRAPPED_KEY_FILE="${WORK_DIR}/wrapped_key.bin"
CEK_FILE="${WORK_DIR}/cek.bin"
printf '%s' "${WRAPPED_KEY_B64}" | base64 -d | head -c 16 > "${WRAPPED_KEY_FILE}"
openssl enc -d -aes-256-cbc -nopad \
  -K "${KEK_HEX}" -iv "${ZERO_IV}" \
  -in "${WRAPPED_KEY_FILE}" -out "${CEK_FILE}"
CEK_HEX=$(xxd -p -c256 "${CEK_FILE}")
if (( ${#CEK_HEX} != 32 )); then
  echo "Unexpected CEK length: ${#CEK_HEX} hex chars (expected 32)" >&2
  exit 1
fi

# 3. Download the encrypted EPUB (the streaming endpoint 302s to a signed CDN URL).
ENCRYPTED_FILE="${WORK_DIR}/encrypted.epub.bin"
echo "Downloading encrypted file..." >&2
curl --fail -sL "${FILE_URL}/${ORDER_ID}" -o "${ENCRYPTED_FILE}"
echo "Downloaded $(wc -c < "${ENCRYPTED_FILE}") bytes" >&2

# 4. Decrypt the file in one pass with AES-128-CTR.
DECRYPTED_FILE="${WORK_DIR}/decrypted.epub"
openssl enc -d -aes-128-ctr \
  -K "${CEK_HEX}" -iv "${ZERO_IV}" \
  -in "${ENCRYPTED_FILE}" -out "${DECRYPTED_FILE}"

# Sanity-check the result is a ZIP.
MAGIC=$(head -c 4 "${DECRYPTED_FILE}" | xxd -p)
if [[ "${MAGIC}" != '504b0304' ]]; then
  echo "Decryption produced non-ZIP output (magic: ${MAGIC}). Wrong key?" >&2
  exit 1
fi

# 5. Place the EPUB at the chosen output path.
if [[ -n "${OUTPUT_OVERRIDE}" ]]; then
  OUTPUT_PATH="${OUTPUT_OVERRIDE}"
else
  # Strip filesystem-hostile characters from the default name.
  SAFE_NAME=$(printf '%s - %s' "${AUTHOR:-unknown}" "${TITLE:-${ORDER_ID}}" | tr '/:\\' '___')
  OUTPUT_PATH="${PWD}/${SAFE_NAME}.epub"
fi
cp -- "${DECRYPTED_FILE}" "${OUTPUT_PATH}"
echo "Wrote ${OUTPUT_PATH}" >&2
