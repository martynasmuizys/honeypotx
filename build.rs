fn main() {
    // THIS IS FOR CUSTOM BUILD! USED FOR SECRET FEATURE!
    if std::path::Path::new("audio/let_it_happen.mp3").exists() {
        println!("cargo::rustc-cfg=audio_available=\"true\"");
    }
}
