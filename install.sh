#!/usr/bin/env bash
# Installs only an explicit, checksum-verified PipeNetwork/pipe release.
set -euo pipefail
umask 077
pipe_prefix="${PIPE_INSTALL_PREFIX:-$HOME/.local}"
pipe_version= pipe_archive= pipe_expected= pipe_rollback=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --version) pipe_version=${2:?--version requires a value}; shift 2 ;;
    --prefix) pipe_prefix=${2:?--prefix requires a value}; shift 2 ;;
    --archive) pipe_archive=${2:?--archive requires a value}; shift 2 ;;
    --sha256) pipe_expected=${2:?--sha256 requires a value}; shift 2 ;;
    --rollback) pipe_rollback=1; shift ;;
    *) printf 'Usage: install.sh --version VERSION [--prefix DIR] [--archive FILE --sha256 HASH]\n       install.sh --rollback [--prefix DIR]\n' >&2; exit 2 ;;
  esac
done
[[ "$pipe_prefix" == /* && "$pipe_prefix" != / ]] || { echo 'Installation prefix must be an absolute directory.' >&2; exit 2; }
mkdir -p "$pipe_prefix/bin" "$pipe_prefix/share/pipe-installer/backups"
pipe_state="$pipe_prefix/share/pipe-installer"
mkdir "$pipe_state/lock" 2>/dev/null || { echo 'Another installation is active; inspect the retained lock before retrying.' >&2; exit 1; }
pipe_temp=$(mktemp -d "$pipe_state/work.XXXXXX")
trap 'rm -rf -- "$pipe_temp"; rmdir "$pipe_state/lock"' EXIT
pipe_sha() { if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | cut -d' ' -f1; else shasum -a 256 "$1" | cut -d' ' -f1; fi; }
pipe_destination="$pipe_prefix/bin/pipe"
# Never follow a caller's existing link when replacing or backing up a binary.
[[ ! -d "$pipe_destination" ]] || { echo 'Installation destination is a directory.' >&2; exit 1; }
if [[ "$pipe_rollback" == 1 ]]; then
  [[ -z "$pipe_version$pipe_archive$pipe_expected" && -f "$pipe_state/previous" ]] || { echo 'No recorded previous binary is available.' >&2; exit 1; }
  read -r pipe_previous pipe_previous_hash < "$pipe_state/previous"
  [[ "$pipe_previous" =~ ^[a-f0-9]{64}$ && "$pipe_previous_hash" == "$pipe_previous" ]] || { echo 'Invalid rollback record.' >&2; exit 1; }
  pipe_source="$pipe_state/backups/$pipe_previous"
  [[ -f "$pipe_source" && $(pipe_sha "$pipe_source") == "$pipe_previous_hash" ]] || { echo 'Previous binary checksum changed.' >&2; exit 1; }
else
  pipe_version=${pipe_version#v}
  [[ "$pipe_version" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[A-Za-z0-9.]+)?$ ]] || { echo 'An explicit semantic --version is required.' >&2; exit 2; }
  case "$(uname -s):$(uname -m)" in
    Linux:x86_64) pipe_target=x86_64-unknown-linux-gnu ;;
    Linux:aarch64|Linux:arm64) pipe_target=aarch64-unknown-linux-gnu ;;
    Darwin:x86_64) pipe_target=x86_64-apple-darwin ;;
    Darwin:arm64) pipe_target=aarch64-apple-darwin ;;
    *) echo 'Unsupported platform. See the release target list.' >&2; exit 1 ;;
  esac
  pipe_name="pipe-v$pipe_version-$pipe_target.tar.gz"
  if [[ -n "$pipe_archive" ]]; then
    [[ "$pipe_expected" =~ ^[a-f0-9]{64}$ ]] || { echo 'Offline installation requires the independently verified --sha256.' >&2; exit 2; }
    cp -- "$pipe_archive" "$pipe_temp/$pipe_name"
  else
    [[ -z "$pipe_expected" ]] || { echo '--sha256 is only accepted with --archive.' >&2; exit 2; }
    command -v gh >/dev/null 2>&1 || { echo 'Install GitHub CLI to verify signed provenance, or use a verified offline archive.' >&2; exit 1; }
    pipe_url="https://github.com/PipeNetwork/pipe/releases/download/v$pipe_version"
    curl --proto '=https' --tlsv1.2 --fail --location --silent --show-error "$pipe_url/$pipe_name" -o "$pipe_temp/$pipe_name"
    curl --proto '=https' --tlsv1.2 --fail --location --silent --show-error "$pipe_url/SHA256SUMS" -o "$pipe_temp/SHA256SUMS"
    pipe_expected=$(awk -v name="$pipe_name" '$2 == name {print $1}' "$pipe_temp/SHA256SUMS")
    [[ "$pipe_expected" =~ ^[a-f0-9]{64}$ ]] || { echo 'Archive is missing from release checksums.' >&2; exit 1; }
    gh attestation verify "$pipe_temp/$pipe_name" --repo PipeNetwork/pipe --source-ref "refs/tags/v$pipe_version" >/dev/null
  fi
  [[ $(pipe_sha "$pipe_temp/$pipe_name") == "$pipe_expected" ]] || { echo 'Archive checksum mismatch; existing installation was preserved.' >&2; exit 1; }
  # Extract only a single expected member, never arbitrary paths from an archive.
  [[ $(tar -tzf "$pipe_temp/$pipe_name" | awk '$0 == "pipe" {n++} END {print n+0}') == 1 ]] || { echo 'Archive must contain exactly one pipe binary.' >&2; exit 1; }
  [[ $(tar -tvzf "$pipe_temp/$pipe_name" pipe | cut -c1) == - ]] || { echo 'Archive binary is not a regular file.' >&2; exit 1; }
  tar -xOzf "$pipe_temp/$pipe_name" pipe > "$pipe_temp/pipe"
  chmod 700 "$pipe_temp/pipe"
  [[ $("$pipe_temp/pipe" --version) == "pipe $pipe_version" ]] || { echo 'Binary version differs from the requested release.' >&2; exit 1; }
  pipe_source="$pipe_temp/pipe"
fi
if [[ -e "$pipe_destination" || -L "$pipe_destination" ]]; then
  [[ -f "$pipe_destination" ]] || { echo 'Existing destination is not a usable binary.' >&2; exit 1; }
  pipe_old_hash=$(pipe_sha "$pipe_destination")
  if [[ ! -e "$pipe_state/backups/$pipe_old_hash" ]]; then cp -- "$pipe_destination" "$pipe_state/backups/$pipe_old_hash"; fi
  [[ $(pipe_sha "$pipe_state/backups/$pipe_old_hash") == "$pipe_old_hash" ]] || { echo 'Backup checksum differs.' >&2; exit 1; }
  printf '%s %s\n' "$pipe_old_hash" "$pipe_old_hash" > "$pipe_temp/previous"
else
  : > "$pipe_temp/previous"
fi
# Both renames stay on the destination filesystem. Config, keyring and journals are untouched.
pipe_install_temp=$(mktemp "$pipe_prefix/bin/.pipe.installing.XXXXXX")
cp -- "$pipe_source" "$pipe_install_temp"
chmod 755 "$pipe_install_temp"
mv -f -- "$pipe_install_temp" "$pipe_destination"
if [[ -s "$pipe_temp/previous" ]]; then mv -f -- "$pipe_temp/previous" "$pipe_state/previous"; fi
printf 'Installed %s at %s\n' "$("$pipe_destination" --version)" "$pipe_destination"
printf 'Add %s to PATH if needed. Existing configuration and recovery records are retained.\n' "$pipe_prefix/bin"
