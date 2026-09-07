#!/bin/sh
# Mobile acceptance harness: everything checkable about the Android/iOS
# clients without a device, an SDK install, or a signing identity.
#
# Device-gated (and therefore NOT claimed here): MediaCodec decode on
# arm64/x86_64 hardware, VideoToolbox presentation on a phone, signed-store
# install, background radio behavior, thermal-chamber runs.
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
lowlat="$root/engine/lowlat"
fail=0

check() {
    if eval "$2"; then
        printf 'ok   %s\n' "$1"
    else
        printf 'FAIL %s\n' "$1"
        fail=1
    fi
}

check "mobile-ffi unit tests (policy + null-handle FFI)" \
    "cargo test --locked --manifest-path '$lowlat/Cargo.toml' -p openstream-mobile-ffi -- --test-threads=1 >/dev/null 2>&1"

check "C header declares pause/thermal APIs" \
    "grep -q openstream_client_set_paused '$root/include/openstream_client.h' &&
     grep -q openstream_client_set_thermal '$root/include/openstream_client.h'"

check "JNI bridges pause/thermal" \
    "grep -q nativeSetPaused '$root/mobile/android/app/src/main/cpp/openstream_jni.cpp' &&
     grep -q nativeSetThermal '$root/mobile/android/app/src/main/cpp/openstream_jni.cpp'"

check "Kotlin declares pause/thermal/lifecycle hooks" \
    "grep -q nativeSetPaused '$root/mobile/android/app/src/main/java/app/openstream/OpenStreamNative.kt' &&
     grep -q onPause '$root/mobile/android/app/src/main/java/app/openstream/MainActivity.kt' &&
     grep -q onResume '$root/mobile/android/app/src/main/java/app/openstream/MainActivity.kt' &&
     grep -q ThermalStatus '$root/mobile/android/app/src/main/java/app/openstream/MainActivity.kt'"

check "Swift declares pause/thermal/lifecycle hooks" \
    "grep -q setPaused '$root/mobile/ios/OpenStreamSession.swift' &&
     grep -q setThermalLevel '$root/mobile/ios/OpenStreamSession.swift' &&
     grep -q viewDidDisappear '$root/mobile/ios/OpenStreamViewController.swift' &&
     grep -q thermalStateDidChangeNotification '$root/mobile/ios/OpenStreamViewController.swift'"

check "release signing template exists and keystore is untracked" \
    "test -f '$root/mobile/android/signing.properties.example' &&
     ! test -f '$root/mobile/android/signing.properties'"

# Symbol check on a host-built bridge: the lifecycle APIs must be exported.
if cargo build --locked --manifest-path "$lowlat/Cargo.toml" -p openstream-mobile-ffi >/dev/null 2>&1; then
    lib=$(find "$lowlat/target/debug" -maxdepth 1 \( -name 'libopenstream_mobile_ffi.dylib' -o -name 'libopenstream_mobile_ffi.so' -o -name 'libopenstream_mobile_ffi.a' \) | head -n 1)
    if [ -n "${lib:-}" ] && command -v nm >/dev/null 2>&1; then
        check "bridge exports pause/thermal symbols" \
            "nm -g '$lib' 2>/dev/null | grep -q openstream_client_set_paused &&
             nm -g '$lib' 2>/dev/null | grep -q openstream_client_set_thermal"
    else
        printf 'skip bridge symbol check (no nm or no host cdylib)\n'
    fi
else
    printf 'FAIL mobile-ffi host build\n'
    fail=1
fi

if [ "$fail" -ne 0 ]; then
    printf 'mobile acceptance: NOT READY (see FAIL lines; device runs still required)\n'
    exit 1
fi
printf 'mobile acceptance (host-checkable surface): READY\n'
