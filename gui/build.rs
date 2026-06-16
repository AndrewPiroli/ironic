fn main() {
    if cfg!(target_os = "windows") {
        use embed_manifest::*;
        use embed_manifest::manifest::*;
        println!("cargo:rerun-if-changed=build.rs");
        let manifest = new_manifest("ironic.andrewtech.net")
            .active_code_page(ActiveCodePage::Utf8)
            .requested_execution_level(ExecutionLevel::AsInvoker)
            .scrolling_awareness(ScrollingAwareness::UltraHighResolution)
            .long_path_aware(Setting::Enabled)
            .dpi_awareness(DpiAwareness::PerMonitorV2)
            .supported_os(SupportedOS::Windows10..)
            .heap_type(HeapType::SegmentHeap);
        embed_manifest(manifest).unwrap();
    }
    let config = slint_build::CompilerConfiguration::new().with_style("cupertino".into());
    slint_build::compile_with_config("ui/app-window.slint", config).expect("Slint build failed");
}