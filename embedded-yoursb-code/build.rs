use std::{env, path::PathBuf, todo};

use bindgen::{Builder, CargoCallbacks};
use cmake::Config;

fn main() {
    // build dependency
    let dst = Config::new("third_party/libclipboard").build();
    println!(
        "cargo:rustc-link-search=native={}",
        dst.join("lib").display()
    );
    println!("cargo:rustc-link-lib=clipboard");

    match std::env::var("CARGO_CFG_TARGET_OS")
        .expect("No OS")
        .as_str()
    {
        "windows" => {
            todo!()
        }
        "macos" => {
            todo!()
        }
        "linux" => {
            println!("cargo:rustc-link-lib=xcb");
            println!("cargo:rustc-link-lib=pthread");
        }
        os => panic!("Unsupported os: {os}"),
    }

    // Other depedencies

    // make bindings
    println!("cargo:rerun-if-changed=c_deps.h");
    let bindings = Builder::default()
        .header("c_deps.h")
        .clang_args(["-I", &dst.join("include").to_string_lossy()])
        .parse_callbacks(Box::new(CargoCallbacks))
        .use_core()
        .generate()
        .expect("Unable to generate bindings");

    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings
        .write_to_file(out_path.join("bindings.rs"))
        .expect("Couldn't write bindings!");
}
