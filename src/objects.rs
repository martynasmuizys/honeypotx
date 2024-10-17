use std::path::Path;

use anyhow::Context;
use libbpf_rs::{Object, ObjectBuilder};

pub fn get_object(builder: &mut ObjectBuilder, path: &Path) -> Result<Object, anyhow::Error> {
    let open_object = builder
        .open_file(path)
        .with_context(|| format!("Failed to open object file {:?}", path))?;
    let object = open_object
        .load()
        .with_context(|| format!("Failed to load BPF program"))?;
    Ok(object)
}
