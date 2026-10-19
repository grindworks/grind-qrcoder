#!/bin/bash
# Build styles.css from input.css with the pinned Tailwind CSS standalone binary.
# The binary for this OS/CPU is downloaded on first run and verified against the pinned SHA-256.
set -euo pipefail
cd "$(dirname "$0")"

TAILWIND_VERSION="4.2.4"

case "$(uname -s)-$(uname -m)" in
  Darwin-arm64)          ASSET="tailwindcss-macos-arm64";     SHA256="932f7045205283f4b26f9a4c3f027958526bf5bcc8577a7e2f18002e1eb5145e" ;;
  Darwin-x86_64)         ASSET="tailwindcss-macos-x64";       SHA256="4fcbbf4e680e462365a41feaaf4414f92c25f5bcc0a7729a62432c05e8173733" ;;
  Linux-x86_64)          ASSET="tailwindcss-linux-x64";       SHA256="cabeef049cdeab61a5fa6b65ea28a3e8e53b8a85e58883947868c730fc48bdec" ;;
  Linux-aarch64|Linux-arm64) ASSET="tailwindcss-linux-arm64"; SHA256="30fa5ad8d26e8f5aaeb7e500da6015543c5bbbfb7d7d775b83fbc3fb9cd5ef7c" ;;
  MINGW*-x86_64|MSYS*-x86_64|CYGWIN*-x86_64) ASSET="tailwindcss-windows-x64.exe"; SHA256="28075cba911f978519ed7cd5fa543755b601a85922fe5978097911902ddeee86" ;;
  *) echo "Unsupported platform: $(uname -s) $(uname -m)" >&2; exit 1 ;;
esac

sha256_of() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | cut -d' ' -f1; else shasum -a 256 "$1" | cut -d' ' -f1; fi
}

BINARY="./${ASSET}"
if [ ! -f "$BINARY" ] || [ "$(sha256_of "$BINARY")" != "$SHA256" ]; then
  echo "Downloading Tailwind CSS v${TAILWIND_VERSION} (${ASSET})..."
  curl -fsSL -o "${BINARY}.download" "https://github.com/tailwindlabs/tailwindcss/releases/download/v${TAILWIND_VERSION}/${ASSET}"
  if [ "$(sha256_of "${BINARY}.download")" != "$SHA256" ]; then
    rm -f "${BINARY}.download"
    echo "Checksum mismatch for ${ASSET}; aborting." >&2
    exit 1
  fi
  mv "${BINARY}.download" "$BINARY"
  chmod +x "$BINARY"
fi

"$BINARY" -i ./input.css -o ./styles.css --minify
