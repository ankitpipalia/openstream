//! Captures the commit this binary was built from, for `/version`.
//!
//! Without this, a deployed `/healthz` answering `200 ok` proves the process
//! is alive but not which revision is actually running -- exactly the gap
//! that makes a bad deploy hard to distinguish from a stale one.

fn main() {
    // A CI-run build always has GITHUB_SHA (a GitHub Actions default env var,
    // accurate for that checkout even in a shallow clone where `git
    // rev-parse` would still work anyway, but this avoids depending on `git`
    // being on the builder's PATH at all). A packaging script can set
    // OPENSTREAM_BUILD_SHA directly to override either source.
    let sha = std::env::var("OPENSTREAM_BUILD_SHA")
        .or_else(|_| std::env::var("GITHUB_SHA"))
        .ok()
        .or_else(|| {
            std::process::Command::new("git")
                .args(["rev-parse", "HEAD"])
                .output()
                .ok()
                .filter(|output| output.status.success())
                .and_then(|output| String::from_utf8(output.stdout).ok())
                .map(|sha| sha.trim().to_string())
        })
        .unwrap_or_else(|| "unknown".to_string());
    println!("cargo:rustc-env=OPENSTREAM_BUILD_SHA={sha}");
    println!("cargo:rerun-if-env-changed=OPENSTREAM_BUILD_SHA");
    println!("cargo:rerun-if-env-changed=GITHUB_SHA");
}
