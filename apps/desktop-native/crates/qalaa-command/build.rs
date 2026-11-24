fn main() {
    // Debug builds (and so `cargo test`) keep element debug info, which Slint's
    // testing backend needs to find elements by their accessible labels.
    let debug = std::env::var("PROFILE").map(|p| p == "debug").unwrap_or(false);
    let config = slint_build::CompilerConfiguration::new()
        .with_style("fluent".into())
        .with_debug_info(debug);
    slint_build::compile_with_config("ui/app.slint", config).expect("Slint UI compiles");
}
