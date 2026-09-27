// Which release archive this binary updates itself from. Releases ship static musl builds,
// so a local glibc build maps to the matching musl artifact.
fn main() {
    let target = std::env::var("TARGET").unwrap();
    let release_target = target.replace("-gnueabihf", "-musleabihf").replace("-gnu", "-musl");
    println!("cargo:rustc-env=MESHVPN_RELEASE_TARGET={release_target}");
    println!("cargo:rerun-if-changed=build.rs");
}
