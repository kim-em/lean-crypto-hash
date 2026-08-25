#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "$0")/../.." && pwd)
cd "$repo_root"

if ! cmp -s lean-toolchain validation/lean-toolchain; then
  echo 'root and downstream lean-toolchain pins differ' >&2
  exit 1
fi

if ! grep -Eq '"packages"[[:space:]]*:[[:space:]]*\[[[:space:]]*\]' lake-manifest.json; then
  echo 'root lake-manifest.json contains a package dependency' >&2
  exit 1
fi

if grep -REn '@\[extern|foreign import|IO\.Process|Std\.Net|IO\.net' Crypto Crypto.lean Test.lean \
    md5sum.lean sha1sum.lean sha224sum.lean sha256sum.lean sha384sum.lean sha512sum.lean \
    sha512_224sum.lean sha512_256sum.lean \
    sha3_224sum.lean sha3_256sum.lean sha3_384sum.lean sha3_512sum.lean \
    shake128sum.lean shake256sum.lean; then
  echo 'root package contains FFI or external-process code' >&2
  exit 1
fi

if find . -path './.git' -prune -o -path './.lake' -prune -o -path './validation' -prune -o \
    -type f \( -name '*.c' -o -name '*.h' -o -name '*.cc' -o -name '*.cpp' \) -print | grep -q .; then
  echo 'root package contains authored C/C++ sources' >&2
  exit 1
fi

if grep -nE '^(public[[:space:]]+)?import Crypto\.CLI[[:space:]]*$' Crypto.lean ||
    find Crypto -type f -name '*.lean' ! -path 'Crypto/CLI.lean' \
      -exec grep -nHE '^(public[[:space:]]+)?import Crypto\.CLI[[:space:]]*$' {} +; then
  echo 'import Crypto unexpectedly pulls in the CLI' >&2
  exit 1
fi

if grep -nE '^public import Crypto\.(MD5|SHA1|SHA2|SHA3)(\.|[[:space:]]|$)' \
    Crypto.lean Crypto/Hash.lean; then
  echo 'public API imports an implementation module transitively' >&2
  exit 1
fi

while IFS= read -r source; do
  if ! grep -Eq '^[[:space:]]*module[[:space:]]*$' "$source"; then
    echo "Lean source is missing a module declaration: $source" >&2
    exit 1
  fi
done < <(find . -path './.git' -prune -o -path './.lake' -prune -o \
  -path './validation/.lake' -prune -o -type f -name '*.lean' -print)

if grep -REn 'buffer[[:space:]]*\+\+[[:space:]]*input|def[[:space:]]+toBlocks' Crypto; then
  echo 'streaming implementation aggregates an update before compression' >&2
  exit 1
fi

echo 'root dependency/FFI boundary checks passed'
