#!/usr/bin/env bash
set -euo pipefail

# Atomic Red Team T1486 Linux commands adapted to run only inside a sandbox
# rooted under the current experiment run directory.
# Source: atomics/T1486/T1486.md

TEST=""
ROOT="atomic_t1486_lab"
PASSWORD="passwd"

usage() {
  cat <<'USAGE'
Usage:
  t1486_atomic_official.sh --test <gpg|7z|ccrypt|openssl> [--root <subdir>] [--password <pw>]

Safety:
  --root must resolve to a strict subdirectory of the current working directory.
USAGE
}

require_tool() {
  local tool="$1"
  if ! command -v "${tool}" >/dev/null 2>&1; then
    echo "Missing dependency: ${tool}. Install with: make exp-atomic-deps" >&2
    exit 3
  fi
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --test)
      TEST="${2:-}"
      shift 2
      ;;
    --root)
      ROOT="${2:-}"
      shift 2
      ;;
    --password)
      PASSWORD="${2:-}"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown argument: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

if [[ -z "${TEST}" ]]; then
  echo "--test is required" >&2
  usage >&2
  exit 2
fi

CWD="$(pwd -P)"
ROOT_ABS="$(realpath -m "${ROOT}")"

if [[ "${ROOT_ABS}" == "${CWD}" ]]; then
  echo "Safety check failed: refusing to run directly in current directory." >&2
  exit 2
fi

case "${ROOT_ABS}" in
  "${CWD}"/*) ;;
  *)
    echo "Safety check failed: root must be a subdirectory of current working directory." >&2
    exit 2
    ;;
esac

mkdir -p "${ROOT_ABS}"

INPUT_LARGE="${ROOT_ABS}/input_large.txt"
INPUT_SMALL="${ROOT_ABS}/input_small.txt"
printf 'safe-atomic-t1486-sample-data\n%.0s' $(seq 1 2048) > "${INPUT_LARGE}"
printf 'small-rsa-input-sample\n' > "${INPUT_SMALL}"

case "${TEST}" in
  gpg)
    require_tool gpg
    encrypted_file_path="${ROOT_ABS}/passwd.gpg"
    echo "${PASSWORD}" | "$(command -v gpg)" --batch --yes --passphrase-fd 0 --cipher-algo AES256 -o "${encrypted_file_path}" -c "${INPUT_LARGE}"
    ;;
  7z)
    require_tool 7z
    encrypted_file_path="${ROOT_ABS}/passwd.zip"
    "$(command -v 7z)" a -p"${PASSWORD}" "${encrypted_file_path}" "${INPUT_LARGE}" > /dev/null
    ;;
  ccrypt)
    require_tool ccencrypt
    cped_file_path="${ROOT_ABS}/passwd"
    cp "${INPUT_LARGE}" "${cped_file_path}"
    "$(command -v ccencrypt)" -T -K "${PASSWORD}" "${cped_file_path}"
    ;;
  openssl)
    require_tool openssl
    private_key_path="${ROOT_ABS}/key.pem"
    public_key_path="${ROOT_ABS}/pub.pem"
    encrypted_file_path="${ROOT_ABS}/passwd.zip"
    "$(command -v openssl)" genrsa -out "${private_key_path}" 2048 > /dev/null 2>&1
    "$(command -v openssl)" rsa -in "${private_key_path}" -pubout -out "${public_key_path}" > /dev/null 2>&1
    if "$(command -v openssl)" help rsautl >/dev/null 2>&1; then
      "$(command -v openssl)" rsautl -encrypt -inkey "${public_key_path}" -pubin -in "${INPUT_SMALL}" -out "${encrypted_file_path}" > /dev/null 2>&1
    else
      "$(command -v openssl)" pkeyutl -encrypt -pubin -inkey "${public_key_path}" -in "${INPUT_SMALL}" -out "${encrypted_file_path}" -pkeyopt rsa_padding_mode:pkcs1 > /dev/null
    fi
    ;;
  *)
    echo "Unsupported --test '${TEST}'. Expected one of: gpg, 7z, ccrypt, openssl" >&2
    exit 2
    ;;
esac

echo "Atomic T1486 test '${TEST}' completed in sandbox: ${ROOT_ABS}"
