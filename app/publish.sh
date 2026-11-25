#!/usr/bin/env bash
# Package MoonRemote. Usage: ./publish.sh [fd|trimmed|aot|all] [runtime-id]
#   fd      framework-dependent single file (needs .NET 10 runtime)
#   trimmed self-contained, trimmed, compressed single file (default)
#   aot     Native AOT (needs clang/toolchain, same OS only)
set -euo pipefail

mode="${1:-trimmed}"
runtime="${2:-}"
root="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
project="$root/src/MoonRemote/MoonRemote.csproj"

profile_for() {
  case "$1" in
    fd) echo FrameworkDependent ;;
    trimmed) echo SelfContained ;;
    aot) echo NativeAot ;;
    *) echo "unknown mode: $1" >&2; exit 1 ;;
  esac
}

modes=("$mode")
[[ "$mode" == "all" ]] && modes=(fd trimmed aot)

for m in "${modes[@]}"; do
  out="$root/artifacts/publish/$m"
  rm -rf "$out"
  args=(publish "$project" -c Release "-p:PublishProfile=$(profile_for "$m")" -o "$out" -nologo)
  [[ -n "$runtime" ]] && args+=(-r "$runtime")
  echo "==> $m"
  dotnet "${args[@]}"
  echo "    $(du -sh "$out" | cut -f1)  $out"
done
