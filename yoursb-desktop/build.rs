fn main() {
    slint_build::compile("ui/start.slint").unwrap();
    println!("cargo::rerun-if-changed=ui/");
}
