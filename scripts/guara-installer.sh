#!/bin/sh
set -eu

repo="yvyty/guara"
version="${GUARA_VERSION:-}"
install_dir="${GUARA_INSTALL_DIR:-$HOME/.local/bin}"

need() {
    if ! command -v "$1" >/dev/null 2>&1; then
        echo "guara installer: $1 is required" >&2
        exit 1
    fi
}

need curl
need tar
need uname

os=$(uname -s)
arch=$(uname -m)

case "$os" in
    Linux)
        case "$arch" in
            x86_64|amd64) target="x86_64-unknown-linux-gnu" ;;
            *)
                echo "guara installer: unsupported Linux architecture: $arch" >&2
                exit 1
                ;;
        esac
        ;;
    *)
        echo "guara installer: unsupported OS: $os (tagged releases cover Linux and Windows; build from source on macOS)" >&2
        exit 1
        ;;
esac

if [ -z "$version" ]; then
    latest_url=$(curl -fsSLI -o /dev/null -w '%{url_effective}' "https://github.com/$repo/releases/latest")
    version=${latest_url##*/}
fi

case "$version" in
    v*) tag="$version" ;;
    *) tag="v$version" ;;
esac

archive="guara-$tag-$target.tar.gz"
url="https://github.com/$repo/releases/download/$tag/$archive"
tmp=$(mktemp -d "${TMPDIR:-/tmp}/guara-install.XXXXXX")
trap 'rm -rf "$tmp"' EXIT

echo "downloading $url"
curl -fsSL "$url" -o "$tmp/$archive"
tar -xzf "$tmp/$archive" -C "$tmp"
mkdir -p "$install_dir"
cp "$tmp/guara" "$install_dir/guara"
chmod 755 "$install_dir/guara"

echo "installed $install_dir/guara"
case ":$PATH:" in
    *":$install_dir:"*) ;;
    *) echo "add $install_dir to PATH to run guara" ;;
esac
