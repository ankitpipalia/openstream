//! Live screen-capture probe for the native macOS host path.
//!
//! Captures one frame from the main display through `CGDisplayCreateImage` and
//! prints its geometry plus content statistics. A denied Screen Recording
//! permission surfaces as `Unavailable` (no image at all); a real capture
//! reports many distinct byte values and a high non-zero fraction, which a
//! black or empty frame cannot. This is the macOS counterpart to the Linux
//! `export_probe`: a stable-path binary that can be granted a TCC entry and run
//! to prove the capture path end to end, without a GUI.
//!
//! Run: `cargo run -p openstream-macos-host --example capture_probe`

#[cfg(target_os = "macos")]
fn main() -> std::process::ExitCode {
    use openstream_macos_host::capture::ScreenCapture;

    let mut capture = ScreenCapture::main();
    let frame = match capture.capture() {
        Ok(frame) => frame,
        Err(err) => {
            eprintln!("capture failed: {err}");
            return std::process::ExitCode::from(2);
        }
    };

    // Content statistics: a real screen has wide byte diversity; a black or
    // denied frame is all (or almost all) zero. Sample the whole buffer.
    let mut seen = [false; 256];
    let mut non_zero = 0usize;
    let mut sum = 0u64;
    for &b in &frame.bgra {
        seen[usize::from(b)] = true;
        if b != 0 {
            non_zero += 1;
        }
        sum += u64::from(b);
    }
    let distinct = seen.iter().filter(|&&s| s).count();
    let total = frame.bgra.len().max(1);
    let non_zero_pct = (non_zero as f64 / total as f64) * 100.0;
    let mean = sum as f64 / total as f64;

    let head: Vec<String> = frame
        .bgra
        .iter()
        .take(16)
        .map(|b| format!("{b:02x}"))
        .collect();

    println!("{{");
    println!("  \"width\": {},", frame.width);
    println!("  \"height\": {},", frame.height);
    println!("  \"bytes\": {},", frame.bgra.len());
    println!("  \"distinct_byte_values\": {distinct},");
    println!("  \"non_zero_pct\": {non_zero_pct:.2},");
    println!("  \"mean_byte\": {mean:.2},");
    println!("  \"first_16_bytes_bgra\": \"{}\",", head.join(" "));
    // A real screenshot is diverse and mostly non-zero; assert enough to make a
    // black/denied frame fail loudly rather than pass silently.
    let looks_real = distinct > 32 && non_zero_pct > 5.0;
    println!("  \"looks_like_real_screen\": {looks_real}");
    println!("}}");

    if looks_real {
        std::process::ExitCode::SUCCESS
    } else {
        eprintln!(
            "frame captured but content looks empty (distinct={distinct}, non_zero={non_zero_pct:.2}%)"
        );
        std::process::ExitCode::from(3)
    }
}

#[cfg(not(target_os = "macos"))]
fn main() {
    eprintln!("capture_probe is macOS-only");
}
