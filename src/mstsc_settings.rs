//! Validated MSTSC profile settings shared by the editor, RDP exchange and Windows host.
use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub struct Setting {
    pub key: &'static str,
    pub label: &'static str,
    pub group: &'static str,
    pub default: u32,
    pub choices: &'static [(u32, &'static str)],
    pub native_only: bool,
}
const BOOL: &[(u32, &str)] = &[(0, "Off"), (1, "On")];
macro_rules! setting {
    ($key:literal, $label:literal, $group:literal, $default:expr, $choices:expr, $native:expr) => {
        Setting {
            key: $key,
            label: $label,
            group: $group,
            default: $default,
            choices: $choices,
            native_only: $native,
        }
    };
}
pub static SETTINGS: &[Setting] = &[
    setting!(
        "session bpp",
        "Color depth",
        "Display",
        32,
        &[(16, "16 bit"), (24, "24 bit"), (32, "32 bit")],
        false
    ),
    setting!(
        "screen mode id",
        "Display mode",
        "Display",
        1,
        &[(1, "Window"), (2, "Full screen")],
        true
    ),
    setting!(
        "use multimon",
        "Use all local monitors",
        "Display",
        0,
        BOOL,
        true
    ),
    setting!(
        "displayconnectionbar",
        "Show connection bar in full screen",
        "Display",
        1,
        BOOL,
        true
    ),
    setting!(
        "keyboardhook",
        "Apply Windows key combinations",
        "Local resources",
        2,
        &[
            (0, "On this computer"),
            (1, "On the remote computer"),
            (2, "Only in full screen")
        ],
        true
    ),
    setting!(
        "audiomode",
        "Remote audio playback",
        "Local resources",
        2,
        &[
            (0, "On this computer"),
            (1, "On the remote computer"),
            (2, "Do not play")
        ],
        true
    ),
    setting!(
        "redirectprinters",
        "Printers",
        "Local resources",
        0,
        BOOL,
        true
    ),
    setting!(
        "redirectsmartcards",
        "Smart cards",
        "Local resources",
        0,
        BOOL,
        true
    ),
    setting!(
        "redirectcomports",
        "Serial / COM ports",
        "Local resources",
        0,
        BOOL,
        true
    ),
    setting!(
        "redirectposdevices",
        "Supported POS devices",
        "Local resources",
        0,
        BOOL,
        true
    ),
    setting!(
        "disable wallpaper",
        "Disable desktop background",
        "Experience",
        0,
        BOOL,
        false
    ),
    setting!(
        "allow font smoothing",
        "Font smoothing",
        "Experience",
        1,
        BOOL,
        false
    ),
    setting!(
        "allow desktop composition",
        "Desktop composition",
        "Experience",
        0,
        BOOL,
        false
    ),
    setting!(
        "disable full window drag",
        "Disable window contents while dragging",
        "Experience",
        1,
        BOOL,
        false
    ),
    setting!(
        "disable menu anims",
        "Disable menu animations",
        "Experience",
        1,
        BOOL,
        false
    ),
    setting!(
        "disable themes",
        "Disable visual styles",
        "Experience",
        0,
        BOOL,
        false
    ),
    setting!(
        "bitmapcachepersistenable",
        "Persistent bitmap caching",
        "Experience",
        0,
        BOOL,
        true
    ),
    setting!(
        "connection type",
        "Connection speed",
        "Experience",
        7,
        &[
            (1, "Modem"),
            (2, "Low-speed broadband"),
            (3, "Satellite"),
            (4, "High-speed broadband"),
            (5, "WAN"),
            (6, "LAN"),
            (7, "Detect automatically")
        ],
        true
    ),
    setting!(
        "bandwidthautodetect",
        "Detect bandwidth automatically",
        "Experience",
        1,
        BOOL,
        true
    ),
    setting!(
        "networkautodetect",
        "Detect network automatically",
        "Experience",
        1,
        BOOL,
        true
    ),
    setting!(
        "authentication level",
        "If server authentication fails",
        "Advanced",
        1,
        &[
            (1, "Do not connect"),
            (2, "Warn me"),
            (0, "Connect without warning")
        ],
        true
    ),
    setting!(
        "enablecredsspsupport",
        "Network Level Authentication (CredSSP)",
        "Advanced",
        1,
        BOOL,
        true
    ),
    setting!(
        "gatewayusagemethod",
        "Gateway usage",
        "Advanced",
        1,
        &[
            (1, "Always use gateway"),
            (2, "Bypass for local addresses"),
            (3, "Use default gateway settings"),
            (4, "Do not use gateway"),
            (0, "Disabled")
        ],
        true
    ),
    setting!(
        "promptcredentialonce",
        "Use connection credentials for gateway",
        "Advanced",
        1,
        BOOL,
        false
    ),
];

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct MstscSettings {
    /// Only recognized, non-secret RDP integer properties belong here.
    values: BTreeMap<String, u32>,
    pub windows_compatibility: bool,
    /// Explicit drive list, e.g. C:;D:;, * or DynamicDrives.
    pub drives: String,
    /// Supported Plug and Play devices: * or DynamicDevices.
    pub devices: String,
}

impl MstscSettings {
    pub fn get(&self, key: &str) -> u32 {
        self.values.get(key).copied().unwrap_or_else(|| {
            SETTINGS
                .iter()
                .find(|s| s.key == key)
                .expect("Known MSTSC setting")
                .default
        })
    }
    pub fn set(&mut self, key: &str, value: u32) -> Result<()> {
        let Some(spec) = SETTINGS.iter().find(|s| s.key == key) else {
            bail!("Unknown RDP setting: {key}")
        };
        if !spec.choices.iter().any(|(v, _)| *v == value) {
            bail!("Invalid value for RDP setting {key}: {value}");
        }
        self.values.insert(key.to_owned(), value);
        Ok(())
    }
    pub fn validate(&self) -> Result<()> {
        for (key, value) in &self.values {
            let mut checked = Self::default();
            checked.set(key, *value)?;
        }
        for value in [&self.drives, &self.devices] {
            if value.len() > 4096 || value.chars().any(char::is_control) {
                bail!("Invalid device redirection list");
            }
        }
        for drive in self.drives.split(';').filter(|s| !s.is_empty()) {
            if drive != "*"
                && drive != "DynamicDrives"
                && !(drive.len() == 2
                    && drive.as_bytes()[0].is_ascii_alphabetic()
                    && drive.ends_with(':'))
            {
                bail!("Drive list must contain drive letters (C:;D:;), * or DynamicDrives");
            }
        }
        if !self.devices.is_empty() && self.devices != "*" && self.devices != "DynamicDevices" {
            bail!("Device list must be empty, * or DynamicDevices");
        }
        Ok(())
    }
    pub fn requires_windows(&self) -> bool {
        self.windows_compatibility
            || !self.drives.is_empty()
            || !self.devices.is_empty()
            || SETTINGS.iter().any(|s| {
                s.native_only && self.get(s.key) != s.default &&
                // Local sound is implemented by IronRDP too.
                !(s.key == "audiomode" && self.get(s.key) == 0) &&
                !(s.key == "gatewayusagemethod" && [0, 4].contains(&self.get(s.key)))
            })
    }
    pub fn performance_flags(&self) -> ironrdp_pdu::rdp::client_info::PerformanceFlags {
        use ironrdp_pdu::rdp::client_info::PerformanceFlags as F;
        let mut flags = F::empty();
        for (key, flag) in [
            ("disable wallpaper", F::DISABLE_WALLPAPER),
            ("disable full window drag", F::DISABLE_FULLWINDOWDRAG),
            ("disable menu anims", F::DISABLE_MENUANIMATIONS),
            ("disable themes", F::DISABLE_THEMING),
            ("allow font smoothing", F::ENABLE_FONT_SMOOTHING),
            ("allow desktop composition", F::ENABLE_DESKTOP_COMPOSITION),
        ] {
            flags.set(flag, self.get(key) == 1);
        }
        flags
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn old_profiles_keep_rust_backend_and_performance_defaults() {
        let s: MstscSettings = serde_json::from_str("{}").unwrap();
        assert!(!s.requires_windows());
        assert_eq!(s.performance_flags(), Default::default());
    }
    #[test]
    fn native_resources_select_windows_but_visual_preferences_do_not() {
        let mut s = MstscSettings::default();
        s.set("disable wallpaper", 1).unwrap();
        s.set("session bpp", 16).unwrap();
        assert!(!s.requires_windows());
        s.set("redirectprinters", 1).unwrap();
        assert!(s.requires_windows());
    }
    #[test]
    fn rejects_invalid_json_and_device_injection() {
        let s: MstscSettings =
            serde_json::from_str(r#"{"values":{"authentication level":99}}"#).unwrap();
        assert!(s.validate().is_err());
        let s = MstscSettings {
            drives: "C:\r\nusername:s:injected".into(),
            ..Default::default()
        };
        assert!(s.validate().is_err());
    }
}
