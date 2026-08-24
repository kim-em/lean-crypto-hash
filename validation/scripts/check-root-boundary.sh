#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "$0")/../.." && pwd)
cd "$repo_root"

if ! rg --quiet --multiline '"packages"\s*:\s*\[\s*\]' lake-manifest.json; then
  echo 'root lake-manifest.json contains a package dependency' >&2
  exit 1
fi

if rg --line-number '@\[extern|foreign import|IO\.Process|Std\.Net|IO\.net' Crypto Crypto.lean Test.lean \
    md5sum.lean sha1sum.lean sha224sum.lean sha256sum.lean sha384sum.lean sha512sum.lean \
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

if rg --quiet '^import Crypto\.CLI$' Crypto.lean Crypto --glob '*.lean' --glob '!CLI.lean'; then
  echo 'import Crypto unexpectedly pulls in the CLI' >&2
  exit 1
fi

echo 'root dependency/FFI boundary checks passed'
