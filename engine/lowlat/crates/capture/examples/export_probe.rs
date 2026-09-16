//! Diagnose NV12 external-memory export capability on the current GPU.
//!
//! Opens the Vulkan device the conversion would use for a DRM node and prints,
//! per external-memory handle type, what the driver claims and whether a
//! single-type allocation actually exports an fd. Run it to tell an
//! intersection defect (each type exportable alone, incompatible together)
//! from a genuine format restriction.
//!
//! Usage: `export_probe [/dev/dri/cardN]` (defaults to card0). Enable the
//! Vulkan validation layer with `VK_INSTANCE_LAYERS=VK_LAYER_KHRONOS_validation`.

fn main() {
    let node = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "/dev/dri/card0".to_string());
    let node = std::path::PathBuf::from(node);
    match lowlat_capture::vulkan::Device::for_display(&node) {
        Ok(device) => {
            println!("vulkan device opened on {}", node.display());
            for line in device.probe_export_capabilities() {
                println!("{line}");
            }
        }
        Err(error) => {
            eprintln!("could not open vulkan device on {}: {error:?}", node.display());
            std::process::exit(1);
        }
    }
}
