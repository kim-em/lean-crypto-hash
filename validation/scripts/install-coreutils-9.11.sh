#!/usr/bin/env bash
set -euo pipefail

install_root=${1:?usage: install-coreutils-9.11.sh INSTALL_ROOT}
build_root=$(mktemp -d)
trap 'rm -rf "$build_root"' EXIT
archive="$build_root/coreutils-9.11.tar.xz"

curl --fail --location --silent --show-error \
  https://ftp.gnu.org/gnu/coreutils/coreutils-9.11.tar.xz \
  --output "$archive"
printf '%s  %s\n' \
  '394024eda0a5955217ceda9cd1201e65dc8fa3aa29c2951135a49521d57c3cc3' \
  "$archive" | sha256sum --check --status

tar --extract --xz --file "$archive" --directory "$build_root"
cd "$build_root/coreutils-9.11"
./configure --quiet --prefix="$install_root"
tools=(md5sum sha1sum sha224sum sha256sum sha384sum sha512sum)
targets=()
for tool in "${tools[@]}"; do targets+=("src/$tool"); done
# Automake's individual program targets omit the generated-header aggregate.
make --jobs=2 -f Makefile -f <(printf '%s\n' 'generated: $(BUILT_SOURCES)') generated
make --jobs=2 "${targets[@]}"
mkdir -p "$install_root/bin"
for tool in "${tools[@]}"; do
  install -m 0755 "src/$tool" "$install_root/bin/$tool"
done
