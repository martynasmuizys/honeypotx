fn main() {
    // THIS IS FOR CUSTOM BUILD! USED FOR SECRET FEATURE!
    if std::path::Path::new("audio/let_it_happen.mp3").exists() {
        println!("cargo::rustc-cfg=audio_available=\"true\"");
    }

    pkg_config::Config::new().probe("openssl").unwrap();
    pkg_config::Config::new().probe("autoconf").unwrap();
    pkg_config::Config::new().probe("autopoint").unwrap();
    pkg_config::Config::new().probe("bison").unwrap();
}
