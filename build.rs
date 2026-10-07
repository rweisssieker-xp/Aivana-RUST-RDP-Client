fn main() {
    println!("cargo:rerun-if-changed=assets/relayne.ico");
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows") {
        winresource::WindowsResource::new()
            .set_icon("assets/relayne.ico")
            .set("ProductName", "Relayne")
            .set("FileDescription", "Relayne Remote Desktop")
            .compile()
            .expect("compile Relayne Windows icon resource");
    }
}
