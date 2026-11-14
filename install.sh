#!/usr/bin/env bash
# Build whatif in release mode and install it as a COPY (never a symlink into this checkout) in a bin
# directory on PATH (default ~/.local/bin), so the installed tool keeps working while the checkout changes.
set -euo pipefail
bin="${1:-$HOME/.local/bin}"
case "$bin" in */bin) ;; *) echo "install.sh: bin directory must end in /bin (cargo installs to <root>/bin): $bin" >&2; exit 2;; esac
mkdir -p "$bin"
here="$(cd "$(dirname "$0")" && pwd)"
# Injected so `whatif --version` reports the checkout it was built from, not the one on disk now.
sha=$(git -C "$here" rev-parse --short HEAD 2>/dev/null || echo unknown)
if [ -n "$(git -C "$here" status --porcelain 2>/dev/null)" ]; then sha="$sha-dirty"; fi
# cargo install replaces an existing file; an old symlink is removed first so the link target is never written through.
if [ -L "$bin/whatif" ]; then rm "$bin/whatif"; fi
(cd "$here" && WHATIF_BUILD_SHA="$sha" WHATIF_BUILD_DATE="$(date +%Y-%m-%d)" cargo install --path . --root "${bin%/bin}" --locked --force --quiet)
echo "installed $bin/whatif (copy, built from $sha): $("$bin/whatif" --version 2>&1 | head -1)"
