use std::{collections::HashMap, os::fd::AsFd};

use anyhow::Context;
use libbpf_rs::{Object, ProgramImpl, Xdp};

use crate::{helpers, Options};

pub fn get_programs<'a>(object: &'a Object) -> Option<HashMap<String, ProgramImpl>> {
    let programs = object.progs();
    let mut ret: HashMap<String, ProgramImpl> = HashMap::new();

    for p in programs {
        let prog_name = p.name().to_str().unwrap();
        ret.insert(prog_name.to_string(), p);
    }

    Some(ret)
}

pub fn attach_xdp<'a>(program: &'a ProgramImpl, options: &Options) -> Result<Xdp<'a>, anyhow::Error> {
    let xdp = Xdp::new(program.as_fd());
    xdp.attach(
        helpers::iface_to_idx(&options.iface)?,
        helpers::get_xdp_flags(&options.xdp_flags)?,
    )
    .with_context(|| format!("Failed to attach BPF program to XDP"))?;
    Ok(xdp)
}

pub fn detach_xdp(xdp: &Xdp, options: &Options) -> Result<(), anyhow::Error> {
    xdp.detach(
        helpers::iface_to_idx(&options.iface)?,
        helpers::get_xdp_flags(&options.xdp_flags)?,
    )
    .with_context(|| format!("Failed to detach BPF program from XDP"))?;
    Ok(())
}
