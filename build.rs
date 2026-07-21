fn main() {
    println!("cargo:rerun-if-changed=src/fuse_shim.cpp");
    println!("cargo:rerun-if-changed=src/fuse_shim.h");

    // Probe fuse3 using pkg-config
    let library = pkg_config::probe_library("fuse3").expect("Failed to find fuse3 via pkg-config");

    let mut builder = cc::Build::new();
    builder.cpp(true); // Compile as C++
    builder.file("src/fuse_shim.cpp");

    // Add include paths from pkg-config
    for path in library.include_paths {
        builder.include(path);
    }

    builder.compile("fuse_shim");

    // Add library search paths and link the library
    for path in library.link_paths {
        println!("cargo:rustc-link-search=native={}", path.to_str().unwrap());
    }
    for lib in library.libs {
        println!("cargo:rustc-link-lib={}", lib);
    }
}
