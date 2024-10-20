use serde::Deserialize;

static DEFAULT_NAME: &str = "Example Program";
static DEFAULT_MAX_IPS: u32 = 32;
static DEFAULT_FREQUENCY: u32 = 1000;
static DEFAULT_WHITELIST_ACTION: &str = "allow";
static DEFAULT_BLACKLIST_ACTION: &str = "deny";
static DEFAULT_GRAYLIST_ACTION: &str = "investigate";

#[derive(Debug, Deserialize)]
pub struct Config {
    pub init: Option<Init>,
}

#[derive(Debug, Deserialize)]
pub struct Init {
    pub name: Option<String>,
    pub whitelist: Option<Whitelist>,
    pub blacklist: Option<Blacklist>,
    pub graylist: Option<Graylist>,
    pub frequency: Option<u32>,
}

#[derive(Debug, Deserialize)]
pub struct Whitelist {
    pub enabled: Option<bool>,
    pub max: Option<u32>,
    pub action: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct Blacklist {
    pub enabled: Option<bool>,
    pub max: Option<u32>,
    pub action: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct Graylist {
    pub enabled: Option<bool>,
    pub max: Option<u32>,
    pub action: Option<String>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            init: Some(Init::default()),
        }
    }
}

impl Default for Init {
    fn default() -> Self {
        Self {
            name: Some(DEFAULT_NAME.to_string()),
            whitelist: Some(Whitelist::default()),
            blacklist: Some(Blacklist::default()),
            graylist: Some(Graylist::default()),
            frequency: Some(DEFAULT_FREQUENCY),
        }
    }
}

impl Default for Whitelist {
    fn default() -> Self {
        Self {
            enabled: Some(false),
            max: Some(DEFAULT_MAX_IPS),
            action: Some(DEFAULT_WHITELIST_ACTION.to_string()),
        }
    }
}

impl Default for Blacklist {
    fn default() -> Self {
        Self {
            enabled: Some(false),
            max: Some(DEFAULT_MAX_IPS),
            action: Some(DEFAULT_BLACKLIST_ACTION.to_string()),
        }
    }
}

impl Default for Graylist {
    fn default() -> Self {
        Self {
            enabled: Some(false),
            max: Some(DEFAULT_MAX_IPS),
            action: Some(DEFAULT_GRAYLIST_ACTION.to_string()),
        }
    }
}

pub trait List {
    fn get_enabled(&self) -> &str;
    fn get_max(&self) -> u32;
    fn get_action(&self) -> &str;
}

impl List for Whitelist {
    fn get_enabled(&self) -> &str {
        todo!()
    }

    fn get_max(&self) -> u32 {
        self.max.unwrap()
    }

    fn get_action(&self) -> &str {
        self.action.as_ref().unwrap()
    }
}

impl List for Blacklist {
    fn get_enabled(&self) -> &str {
        todo!()
    }

    fn get_max(&self) -> u32{
        self.max.unwrap()
    }

    fn get_action(&self) -> &str {
        self.action.as_ref().unwrap()
    }
}

impl List for Graylist {
    fn get_enabled(&self) -> &str {
        todo!()
    }

    fn get_max(&self) -> u32{
        self.max.unwrap()
    }

    fn get_action(&self) -> &str {
        self.action.as_ref().unwrap()
    }
}
