#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "$0")/../.." && pwd)
tool_root="$repo_root/.lake/build/bin"
test_root=$(mktemp -d)
trap 'rm -rf "$test_root"' EXIT

oracle_version=$(md5sum --version | head -1)
if [[ "$oracle_version" != "md5sum (GNU coreutils) 9.11" ]]; then
  echo "expected GNU coreutils 9.11 oracle, got: $oracle_version" >&2
  exit 1
fi

printf '\000\377abc\200\012\000' > "$test_root/binary"
printf 'payload' > "$test_root/name\\with\\slashes"
newline_name="$test_root/name
with
newlines"
printf 'payload' > "$newline_name"
separator_name="$test_root/name) = tricky"
printf 'payload' > "$separator_name"

tools=(md5sum sha1sum sha224sum sha256sum sha384sum sha512sum)
for tool in "${tools[@]}"; do
  system_tool=$(command -v "$tool")
  lean_tool="$tool_root/$tool"

  "$system_tool" "$test_root/binary" > "$test_root/system.out"
  "$lean_tool" "$test_root/binary" > "$test_root/lean.out"
  cmp "$test_root/system.out" "$test_root/lean.out"

  "$system_tool" "$test_root/name\\with\\slashes" "$newline_name" > "$test_root/system.out"
  "$lean_tool" "$test_root/name\\with\\slashes" "$newline_name" > "$test_root/lean.out"
  cmp "$test_root/system.out" "$test_root/lean.out"
  "$lean_tool" --check "$test_root/system.out" > "$test_root/lean-status.out"
  "$system_tool" --check "$test_root/system.out" > "$test_root/system-status.out"
  cmp "$test_root/lean-status.out" "$test_root/system-status.out"
  "$lean_tool" --check "$test_root/lean.out" > "$test_root/lean-status.out"
  "$system_tool" --check "$test_root/lean.out" > "$test_root/system-status.out"
  cmp "$test_root/lean-status.out" "$test_root/system-status.out"

  "$system_tool" --tag "$test_root/name\\with\\slashes" "$separator_name" > "$test_root/system.out"
  "$lean_tool" --tag "$test_root/name\\with\\slashes" "$separator_name" > "$test_root/lean.out"
  cmp "$test_root/system.out" "$test_root/lean.out"
  "$lean_tool" --check "$test_root/system.out" > "$test_root/lean-status.out"
  "$system_tool" --check "$test_root/system.out" > "$test_root/system-status.out"
  cmp "$test_root/lean-status.out" "$test_root/system-status.out"

  "$system_tool" --zero "$test_root/name\\with\\slashes" > "$test_root/system.out"
  "$lean_tool" --zero "$test_root/name\\with\\slashes" > "$test_root/lean.out"
  cmp "$test_root/system.out" "$test_root/lean.out"

  "$system_tool" "$test_root/binary" > "$test_root/system.check"
  "$lean_tool" --check "$test_root/system.check" >/dev/null
  "$lean_tool" "$test_root/binary" > "$test_root/lean.check"
  "$system_tool" --check "$test_root/lean.check" >/dev/null
done

for variant in 224 256; do
  lean_tool="$tool_root/sha512_${variant}sum"
  printf '\000\377abc\200\012\000' | "$lean_tool" | cut -d' ' -f1 > "$test_root/sha512t.out"
  printf '\000\377abc\200\012\000' |
    openssl dgst "-sha512-$variant" -binary | od -An -v -tx1 | tr -d ' \n' > "$test_root/openssl.out"
  printf '\n' >> "$test_root/openssl.out"
  cmp "$test_root/sha512t.out" "$test_root/openssl.out"

  "$lean_tool" "$test_root/binary" > "$test_root/sha512t.check"
  "$lean_tool" --check "$test_root/sha512t.check" >/dev/null
done

printf '\000\377abc\200\012\000' | "$tool_root/sha256sum" > "$test_root/stdin.out"
printf '\000\377abc\200\012\000' | sha256sum > "$test_root/system-stdin.out"
cmp "$test_root/stdin.out" "$test_root/system-stdin.out"

for arg_string in '--tag -c' '--quiet' '--status' '--strict' '--warn' '--ignore-missing' '--zero -c' \
    '--tag --text' '--binary --check' '--text --check'; do
  read -r -a args <<< "$arg_string"
  set +e
  sha256sum "${args[@]}" </dev/null > /dev/null 2> "$test_root/system.err"
  system_status=$?
  "$tool_root/sha256sum" "${args[@]}" </dev/null > /dev/null 2> "$test_root/lean.err"
  lean_status=$?
  set -e
  if [[ $system_status != "$lean_status" ]]; then
    echo "exit-status mismatch for sha256sum $arg_string" >&2
    exit 1
  fi
  head -1 "$test_root/system.err" > "$test_root/system-first.err"
  head -1 "$test_root/lean.err" > "$test_root/lean-first.err"
  cmp "$test_root/system-first.err" "$test_root/lean-first.err"
done

printf 'abc' > "$test_root/commented-input"
sha256sum "$test_root/commented-input" > "$test_root/good.check"
sha256sum -cw "$test_root/good.check" > "$test_root/system.out" 2> "$test_root/system.err"
"$tool_root/sha256sum" -cw "$test_root/good.check" > "$test_root/lean.out" 2> "$test_root/lean.err"
cmp "$test_root/system.out" "$test_root/lean.out"
cmp "$test_root/system.err" "$test_root/lean.err"

{
  printf '# generated checksum list\n'
  cat "$test_root/good.check"
} > "$test_root/commented.check"
: > "$test_root/empty.check"
for opts in '--strict' '--status'; do
  set +e
  sha256sum --check $opts "$test_root/commented.check" "$test_root/empty.check" \
    > "$test_root/system.out" 2> "$test_root/system.err"
  system_status=$?
  "$tool_root/sha256sum" --check $opts "$test_root/commented.check" "$test_root/empty.check" \
    > "$test_root/lean.out" 2> "$test_root/lean.err"
  lean_status=$?
  set -e
  [[ $system_status == "$lean_status" ]]
  cmp "$test_root/system.out" "$test_root/lean.out"
  cmp "$test_root/system.err" "$test_root/lean.err"
done

printf '# provenance\ngarbage\n' > "$test_root/malformed.check"
for opts in '--warn' '--strict'; do
  set +e
  sha256sum --check $opts "$test_root/malformed.check" > "$test_root/system.out" 2> "$test_root/system.err"
  system_status=$?
  "$tool_root/sha256sum" --check $opts "$test_root/malformed.check" > "$test_root/lean.out" 2> "$test_root/lean.err"
  lean_status=$?
  set -e
  [[ $system_status == "$lean_status" ]]
  cmp "$test_root/system.out" "$test_root/lean.out"
  cmp "$test_root/system.err" "$test_root/lean.err"
done

missing_file="$test_root/does-not-exist"
printf '%064d  %s\n' 0 "$missing_file" > "$test_root/missing.check"
set +e
sha256sum --check "$test_root/missing.check" > "$test_root/system.out" 2> "$test_root/system.err"
system_status=$?
"$tool_root/sha256sum" --check "$test_root/missing.check" > "$test_root/lean.out" 2> "$test_root/lean.err"
lean_status=$?
set -e
[[ $system_status == "$lean_status" ]]
cmp "$test_root/system.out" "$test_root/lean.out"
cmp "$test_root/system.err" "$test_root/lean.err"

set +e
sha256sum --check --ignore-missing "$test_root/missing.check" > "$test_root/system.out" 2> "$test_root/system.err"
system_status=$?
"$tool_root/sha256sum" --check --ignore-missing "$test_root/missing.check" > "$test_root/lean.out" 2> "$test_root/lean.err"
lean_status=$?
set -e
[[ $system_status == "$lean_status" ]]
cmp "$test_root/system.out" "$test_root/lean.out"
cmp "$test_root/system.err" "$test_root/lean.err"

for variant in 128 256; do
  shake_tool="$tool_root/shake${variant}sum"
  if printf 'abc' | "$shake_tool" >/dev/null 2>&1; then
    echo "shake${variant}sum accepted a missing output length" >&2
    exit 1
  fi
  printf 'abc' | "$shake_tool" --length 32 | cut -d' ' -f1 > "$test_root/shake.out"
  printf 'abc' | openssl dgst "-shake$variant" -xoflen 32 -binary | od -An -v -tx1 | tr -d ' \n' > "$test_root/openssl.out"
  printf '\n' >> "$test_root/openssl.out"
  cmp "$test_root/shake.out" "$test_root/openssl.out"
  printf 'abc' | "$shake_tool" -l32 | cut -d' ' -f1 > "$test_root/shake.out"
  cmp "$test_root/shake.out" "$test_root/openssl.out"

  rate_minus_one=167
  if [[ $variant == 256 ]]; then rate_minus_one=135; fi
  head -c "$rate_minus_one" /dev/zero > "$test_root/shake-boundary"
  "$shake_tool" --length 400 "$test_root/shake-boundary" | cut -d' ' -f1 > "$test_root/shake.out"
  openssl dgst "-shake$variant" -xoflen 400 -binary < "$test_root/shake-boundary" | od -An -v -tx1 | tr -d ' \n' > "$test_root/openssl.out"
  printf '\n' >> "$test_root/openssl.out"
  cmp "$test_root/shake.out" "$test_root/openssl.out"

  printf '  -\n' > "$test_root/empty-xof.out"
  printf 'abc' | "$shake_tool" --length 0 > "$test_root/shake.out"
  cmp "$test_root/shake.out" "$test_root/empty-xof.out"
done

echo "CLI differential checks passed ($oracle_version and OpenSSL)"
