#!/bin/sh
# Read-only inventory for authorized Parsec artifacts supplied to this
# workspace. It prints metadata and filtered indicators; it never modifies or
# executes the vendor binaries.
set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(CDPATH= cd -- "$script_dir/.." && pwd)

print_file() {
    path=$1
    printf '\n=== %s ===\n' "${path#"$repo_root"/}"
    if command -v file >/dev/null 2>&1; then
        file "$path"
    fi
    if command -v shasum >/dev/null 2>&1; then
        shasum -a 256 "$path"
    elif command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$path"
    fi
}

filter_strings() {
    path=$1
    if ! command -v strings >/dev/null 2>&1; then
        return 0
    fi
    printf '%s\n' '--- filtered strings ---'
    # `-m` keeps a single noisy binary from flooding a report. The complete
    # extracted string lists remain available under analysis/.
    strings -a "$path" 2>/dev/null \
        | rg -i -m 160 'bud|dtls|stun|turn|ice|candidate|relay|hosting_supported|opus|ffmpeg|x264|x265|vaapi|nvenc|pipewire|wayland|x11|alsa|libudev|sctp|websocket|kessel|upnp|uinput|screen.?capture|videotoolbox|desktop.?duplication' \
        || true
}

inspect_elf() {
    path=$1
    if command -v readelf >/dev/null 2>&1; then
        printf '%s\n' '--- ELF dynamic dependencies ---'
        readelf -d "$path" 2>/dev/null | rg 'NEEDED|SONAME|RPATH|RUNPATH' || true
        printf '%s\n' '--- ELF defined dynamic symbols ---'
        readelf --dyn-syms --wide "$path" 2>/dev/null \
            | rg 'GLOBAL.*DEFAULT.*(FUNC|OBJECT)' \
            | tail -80 \
            || true
    fi
}

inspect_macho() {
    path=$1
    if command -v otool >/dev/null 2>&1; then
        printf '%s\n' '--- Mach-O linked libraries ---'
        otool -L "$path" 2>/dev/null || true
    fi
    if command -v nm >/dev/null 2>&1; then
        printf '%s\n' '--- Mach-O external/defined symbol sample ---'
        nm -gU "$path" 2>/dev/null | rg 'wx_main|console_main|hosting|bud|stun|opus|ffmpeg' | head -80 || true
    fi
}

inspect_xapk() {
    if ! command -v unzip >/dev/null 2>&1; then
        return 0
    fi
    printf '%s\n' '--- XAPK manifest ---'
    unzip -p "$1" manifest.json 2>/dev/null | sed -n '1,8p' || true
    printf '%s\n' '--- XAPK native members ---'
    unzip -l "$1" 2>/dev/null | rg 'config|lib/|\.apk$' || true
}

for relative in \
    analysis/deb/usr/share/parsec/skel/parsecd-150-104a.so \
    analysis/win/skel/parsecd-150-104a.dll \
    analysis/parsecd-x86_64.dylib \
    analysis/parsecd-arm64.dylib \
    analysis/parsecd-launcher-arm64 \
    Parsec.app/Contents/Resources/skel/parsecd-150-101a.dylib \
    analysis/win/parsecd.exe \
    analysis/win/pservice.exe \
    Parsec_3.150.097.05.xapk
do
    path=$repo_root/$relative
    if [ -f "$path" ]; then
        print_file "$path"
        filter_strings "$path"
        case "$relative" in
            *.so|*.dll) inspect_elf "$path" ;;
            *.dylib|*launcher*) inspect_macho "$path" ;;
            *.xapk) inspect_xapk "$path" ;;
        esac
    else
        printf '\n--- missing: %s ---\n' "$relative"
    fi
done

printf '\n=== pre-extracted evidence lists ===\n'
for relative in analysis/strings_linux.txt analysis/strings_win_dll.txt \
    analysis/strings_arm64.txt analysis/strings_launcher.txt \
    analysis/strings_vdd.txt analysis/cstring_tokens.txt
do
    path=$repo_root/$relative
    if [ -f "$path" ]; then
        printf '%s\n' "--- $relative: protocol/dependency indicators ---"
        rg -i -m 160 \
            'bud|dtls|stun|turn|ice|candidate|relay|hosting_supported|opus|ffmpeg|x264|x265|vaapi|nvenc|pipewire|wayland|x11|alsa|libudev|sctp|websocket|kessel|upnp|uinput|screen.?capture|videotoolbox|desktop.?duplication' \
            "$path" || true
    fi
done
