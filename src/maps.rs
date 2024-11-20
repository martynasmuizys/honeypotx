use libbpf_rs::{MapCore, MapImpl, Object};

pub fn get_map<'a>(object: &'a Object, name: &'a str) -> Option<MapImpl<'a>> {
    let maps = object.maps();

    for m in maps {
        if m.name() == name {
            return Some(m);
        }
    }

    None
}
