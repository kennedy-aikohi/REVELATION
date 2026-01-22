fn main() {
    // YARA library search path (from env)
    if let Ok(lib) = std::env::var("YARA_LIBRARY_PATH") {
        println!("cargo:rustc-link-search=native={}", lib);
    }

    // vcpkg OpenSSL libs
    println!("cargo:rustc-link-search=native=C:\\vcpkg\\installed\\x64-windows\\lib");

    // Link libyara (static) + OpenSSL (static)
    // NOTE: the order here matters on MSVC.
    println!("cargo:rustc-link-lib=static=libyara");
    println!("cargo:rustc-link-lib=static=libcrypto");
    println!("cargo:rustc-link-lib=static=libssl");

    // OpenSSL on Windows needs these system libs
    println!("cargo:rustc-link-lib=crypt32");
    println!("cargo:rustc-link-lib=advapi32");
    println!("cargo:rustc-link-lib=user32");
}
