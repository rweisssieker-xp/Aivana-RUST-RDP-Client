use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct ProfileOptions {
    pub clipboard: bool,
    pub audio_playback: bool,
    pub microphone: bool,
    pub dynamic_resolution: bool,
    pub auto_reconnect: bool,
    pub width: u16,
    pub height: u16,
    pub monitors: Vec<MonitorLayout>,
    pub shared_folders: Vec<SharedFolder>,
    pub gateway: crate::rd_gateway::GatewayOptions,
}
impl Default for ProfileOptions {
    fn default() -> Self {
        Self {
            clipboard: false,
            audio_playback: false,
            microphone: false,
            dynamic_resolution: true,
            auto_reconnect: true,
            width: 1280,
            height: 800,
            monitors: Vec::new(),
            shared_folders: Vec::new(),
            gateway: Default::default(),
        }
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct MonitorLayout {
    pub x: i32,
    pub y: i32,
    pub width: u32,
    pub height: u32,
    pub primary: bool,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SharedFolder {
    pub name: String,
    pub path: String,
    pub read_only: bool,
}
