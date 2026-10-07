//! In-process Windows Remote Desktop ActiveX host. All methods must run on the UI STA.
//! RemoteApp seamless windows are owned by the control, not an external mstsc process.
use anyhow::{Context, Result, bail};
use std::{marker::PhantomData, rc::Rc};
use windows::{
    Win32::{
        Foundation::{HMODULE, HWND},
        System::{
            Com::{
                DISPATCH_FLAGS, DISPATCH_METHOD, DISPATCH_PROPERTYGET, DISPATCH_PROPERTYPUT,
                DISPPARAMS, IDispatch,
            },
            LibraryLoader::{GetProcAddress, LOAD_LIBRARY_SEARCH_SYSTEM32, LoadLibraryExW},
            Ole::{OleInitialize, OleUninitialize},
            Variant::VARIANT,
        },
        UI::WindowsAndMessaging::{
            CreateWindowExW, DestroyWindow, MoveWindow, SW_HIDE, SW_SHOW, ShowWindow,
            WINDOW_EX_STYLE, WS_CHILD, WS_CLIPCHILDREN, WS_CLIPSIBLINGS,
        },
    },
    core::{GUID, IUnknown, Interface, PCWSTR, s, w},
};

fn invoke(
    object: &IDispatch,
    name: &str,
    flags: DISPATCH_FLAGS,
    mut args: Vec<VARIANT>,
) -> Result<VARIANT> {
    let name_wide: Vec<u16> = name.encode_utf16().chain(Some(0)).collect();
    let mut id = 0;
    let mut put_id = -3; // DISPID_PROPERTYPUT
    args.reverse(); // IDispatch arguments are in reverse order.
    let params = DISPPARAMS {
        rgvarg: args.as_mut_ptr(),
        rgdispidNamedArgs: if flags == DISPATCH_PROPERTYPUT {
            &mut put_id
        } else {
            std::ptr::null_mut()
        },
        cArgs: args.len() as u32,
        cNamedArgs: u32::from(flags == DISPATCH_PROPERTYPUT),
    };
    let mut result = VARIANT::default();
    unsafe {
        object
            .GetIDsOfNames(&GUID::zeroed(), &PCWSTR(name_wide.as_ptr()), 1, 0, &mut id)
            .with_context(|| format!("RDP control property {name} is unavailable"))?;
        object
            .Invoke(
                id,
                &GUID::zeroed(),
                0,
                flags,
                &params,
                Some(&mut result),
                None,
                None,
            )
            .with_context(|| format!("RDP control call {name} failed"))?;
    }
    Ok(result)
}
fn put(object: &IDispatch, name: &str, value: impl Into<VARIANT>) -> Result<()> {
    invoke(object, name, DISPATCH_PROPERTYPUT, vec![value.into()]).map(|_| ())
}
fn child(object: &IDispatch, name: &str) -> Result<IDispatch> {
    Ok(IDispatch::try_from(&invoke(
        object,
        name,
        DISPATCH_PROPERTYGET,
        vec![],
    )?)?)
}

/// The Rc marker prevents this apartment-bound window/COM object moving to a worker.
pub struct NativeRemoteApp {
    window: HWND,
    control: Option<IDispatch>,
    dynamic_resolution: std::cell::Cell<bool>,
    last_size: std::cell::Cell<(i32, i32)>,
    _sta: PhantomData<Rc<()>>,
}

impl NativeRemoteApp {
    /// Create an idle child control. This does not contact a server or authenticate.
    /// `parent` must be the live HWND of the calling UI thread.
    pub fn new(parent: isize) -> Result<Self> {
        if parent == 0 {
            bail!("RemoteApp requires a valid parent window");
        }
        unsafe { OleInitialize(None) }.context("RemoteApp requires a Windows STA UI thread")?;
        let created = (|| -> Result<Self> {
            // Keep ATL loaded for process lifetime: its registered window class has DLL callbacks.
            static ATL: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
            let module = if let Some(handle) = ATL.get() {
                HMODULE(*handle as _)
            } else {
                let module =
                    unsafe { LoadLibraryExW(w!("atl.dll"), None, LOAD_LIBRARY_SEARCH_SYSTEM32) }
                        .context("Windows ATL ActiveX host is not installed")?;
                let _ = ATL.set(module.0 as usize);
                module
            };
            type Init = unsafe extern "system" fn() -> i32;
            type GetControl = unsafe extern "system" fn(
                HWND,
                *mut *mut std::ffi::c_void,
            ) -> windows::core::HRESULT;
            let initialize: Init = unsafe {
                std::mem::transmute(
                    GetProcAddress(module, s!("AtlAxWinInit"))
                        .context("ATL ActiveX initialization is unavailable")?,
                )
            };
            let get_control: GetControl = unsafe {
                std::mem::transmute(
                    GetProcAddress(module, s!("AtlAxGetControl"))
                        .context("ATL ActiveX access is unavailable")?,
                )
            };
            if unsafe { initialize() } == 0 {
                bail!("ATL ActiveX initialization failed");
            }
            let window = unsafe {
                CreateWindowExW(
                    WINDOW_EX_STYLE::default(),
                    w!("AtlAxWin"),
                    w!("{8B918B82-7985-4C24-89DF-C33AD2BBFBCD}"),
                    WS_CHILD | WS_CLIPCHILDREN | WS_CLIPSIBLINGS,
                    0,
                    0,
                    640,
                    480,
                    Some(HWND(parent as _)),
                    None,
                    None,
                    None,
                )
            }
            .context("Unable to embed the Windows RDP control")?;
            let mut raw = std::ptr::null_mut();
            if let Err(error) = unsafe { get_control(window, &mut raw).ok() } {
                unsafe {
                    let _ = DestroyWindow(window);
                }
                return Err(error.into());
            }
            if raw.is_null() {
                unsafe {
                    let _ = DestroyWindow(window);
                }
                bail!("Windows RDP control is not installed");
            }
            let unknown = unsafe { IUnknown::from_raw(raw) };
            let control = match unknown.cast::<IDispatch>() {
                Ok(control) => control,
                Err(error) => {
                    unsafe {
                        let _ = DestroyWindow(window);
                    }
                    return Err(error.into());
                }
            };
            Ok(Self {
                window,
                control: Some(control),
                dynamic_resolution: std::cell::Cell::new(false),
                last_size: std::cell::Cell::new((0, 0)),
                _sta: PhantomData,
            })
        })();
        if created.is_err() {
            unsafe {
                OleUninitialize();
            }
        }
        created
    }

    /// Initiates one connection. The control owns credential/certificate dialogs.
    pub fn connect(
        &self,
        profile: &crate::models::ConnectionProfile,
        app: &crate::remoteapp::RemoteAppOptions,
    ) -> Result<()> {
        self.configure(profile, app)?;
        invoke(
            self.control
                .as_ref()
                .context("RemoteApp control is closed")?,
            "Connect",
            DISPATCH_METHOD,
            vec![],
        )?;
        Ok(())
    }
    fn configure(
        &self,
        profile: &crate::models::ConnectionProfile,
        app: &crate::remoteapp::RemoteAppOptions,
    ) -> Result<()> {
        crate::profile_exchange::export_bytes("rdp", std::slice::from_ref(profile))?;
        if profile.options.gateway.enabled && profile.options.mstsc.get("gatewayusagemethod") != 3 {
            crate::rd_gateway::validate_gateway(&profile.options.gateway, profile.port)?;
        }
        if !app.program.trim().is_empty() {
            crate::remoteapp::validate_options(app)?;
        }
        if profile.options.gateway.enabled && profile.options.gateway.paa {
            bail!(
                "PAA cookies use the native IronRDP gateway connection; the ActiveX host does not support passing them through"
            );
        }
        if !app.working_directory.is_empty() {
            bail!("A working directory is not yet supported for embedded RemoteApps");
        }
        if !profile.options.shared_folders.is_empty() {
            bail!(
                "Windows RDP cannot enforce custom folder or read-only shares. Remove folder shares and select explicit Windows drives, or use the Rust connection mode."
            );
        }
        if !profile.options.monitors.is_empty() {
            bail!(
                "Windows RDP uses local monitor layouts. Remove custom monitor layouts and select Use all local monitors, or use the Rust connection mode."
            );
        }
        let control = self
            .control
            .as_ref()
            .context("RemoteApp control is closed")?;
        put(control, "Server", profile.host.as_str())?;
        put(control, "UserName", profile.username.as_str())?;
        put(control, "Domain", profile.domain.as_str())?;
        let settings = &profile.options.mstsc;
        put(control, "DesktopWidth", i32::from(profile.options.width))?;
        put(control, "DesktopHeight", i32::from(profile.options.height))?;
        put(control, "ColorDepth", settings.get("session bpp") as i32)?;
        put(control, "FullScreen", settings.get("screen mode id") == 2)?;
        let advanced = child(control, "AdvancedSettings9")?;
        put(&advanced, "RDPPort", i32::from(profile.port))?;
        put(
            &advanced,
            "AuthenticationLevel",
            settings.get("authentication level"),
        )?;
        put(
            &advanced,
            "EnableCredSspSupport",
            settings.get("enablecredsspsupport") == 1,
        )?;
        put(&advanced, "RedirectClipboard", profile.options.clipboard)?;
        put(&advanced, "RedirectDrives", !settings.drives.is_empty())?;
        put(
            &advanced,
            "RedirectPrinters",
            settings.get("redirectprinters") == 1,
        )?;
        put(
            &advanced,
            "RedirectSmartCards",
            settings.get("redirectsmartcards") == 1,
        )?;
        put(
            &advanced,
            "RedirectPorts",
            settings.get("redirectcomports") == 1,
        )?;
        put(
            &advanced,
            "RedirectPOSDevices",
            settings.get("redirectposdevices") == 1,
        )?;
        put(&advanced, "RedirectDevices", !settings.devices.is_empty())?;
        put(
            &advanced,
            "AudioCaptureRedirectionMode",
            profile.options.microphone,
        )?;
        let audio_mode = if profile.options.audio_playback {
            0u32
        } else if settings.get("audiomode") == 1 {
            1
        } else {
            2
        };
        put(&advanced, "AudioRedirectionMode", audio_mode)?;
        put(
            &advanced,
            "EnableAutoReconnect",
            profile.options.auto_reconnect,
        )?;
        put(
            &advanced,
            "DisplayConnectionBar",
            settings.get("displayconnectionbar") == 1,
        )?;
        put(
            &advanced,
            "PerformanceFlags",
            settings.performance_flags().bits(),
        )?;
        put(
            &advanced,
            "BitmapPersistence",
            settings.get("bitmapcachepersistenable") as i32,
        )?;
        put(
            &advanced,
            "BandwidthDetection",
            settings.get("bandwidthautodetect") == 1,
        )?;
        let network = if settings.get("networkautodetect") == 1 {
            7
        } else {
            settings.get("connection type").min(6)
        };
        put(&advanced, "NetworkConnectionType", network)?;
        put(&advanced, "SmartSizing", profile.options.dynamic_resolution)?;
        let secured = child(control, "SecuredSettings2")?;
        put(
            &secured,
            "KeyboardHookMode",
            settings.get("keyboardhook") as i32,
        )?;
        crate::native_rdp_resources::configure(control, profile)?;
        let remote = child(control, "RemoteProgram2")?;
        let remote_app = !app.program.trim().is_empty();
        self.dynamic_resolution.set(
            profile.options.dynamic_resolution && !remote_app && settings.get("use multimon") == 0,
        );
        put(&remote, "RemoteProgramMode", remote_app)?;
        if remote_app {
            put(&remote, "RemoteApplicationProgram", app.program.as_str())?;
            put(&remote, "RemoteApplicationName", app.name.as_str())?;
            put(&remote, "RemoteApplicationArgs", app.arguments.as_str())?;
        }
        let gateway = &profile.options.gateway;
        let transport = child(control, "TransportSettings2")?;
        let system_gateway = gateway.enabled && settings.get("gatewayusagemethod") == 3;
        put(
            &transport,
            "GatewayUsageMethod",
            if gateway.enabled {
                settings.get("gatewayusagemethod")
            } else {
                0u32
            },
        )?;
        put(
            &transport,
            "GatewayProfileUsageMethod",
            if system_gateway { 0u32 } else { 1u32 },
        )?;
        if gateway.enabled && !system_gateway {
            put(
                &transport,
                "GatewayHostname",
                format!("{}:{}", gateway.host, gateway.port).as_str(),
            )?;
            put(&transport, "GatewayCredsSource", 0u32)?;
            put(
                &transport,
                "GatewayCredSharing",
                u32::from(gateway.use_profile_credentials),
            )?;
            let (username, domain, password) = if gateway.use_profile_credentials {
                (&profile.username, &profile.domain, &profile.password)
            } else {
                (&gateway.username, &gateway.domain, &gateway.password)
            };
            put(&transport, "GatewayUsername", username.as_str())?;
            put(&transport, "GatewayDomain", domain.as_str())?;
            put(&transport, "GatewayPassword", password.as_str())?;
        }
        Ok(())
    }

    /// Physical pixels relative to the parent HWND client area; hide inactive tabs.
    pub fn place(&self, x: i32, y: i32, width: i32, height: i32, visible: bool) -> Result<()> {
        unsafe {
            MoveWindow(self.window, x, y, width.max(1), height.max(1), true)?;
            let _ = ShowWindow(self.window, if visible { SW_SHOW } else { SW_HIDE });
        }
        let size = (width.clamp(200, 8192) & !1, height.clamp(200, 8192));
        if visible
            && self.dynamic_resolution.get()
            && self.last_size.get() != size
            && self.state()? == 1
        {
            self.last_size.set(size);
            let control = self
                .control
                .as_ref()
                .context("Windows RDP control is closed")?;
            invoke(
                control,
                "UpdateSessionDisplaySettings",
                DISPATCH_METHOD,
                vec![
                    (size.0 as u32).into(),
                    (size.1 as u32).into(),
                    ((size.0 as u32 * 254) / 960).into(),
                    ((size.1 as u32 * 254) / 960).into(),
                    0u32.into(),
                    100u32.into(),
                    100u32.into(),
                ],
            )
            .context("Resize Windows RDP session")?;
        }
        Ok(())
    }
    /// 0 disconnected, 1 connected, 2 connecting (the ActiveX Connected property).
    pub fn state(&self) -> Result<i32> {
        let control = self
            .control
            .as_ref()
            .context("RemoteApp control is closed")?;
        Ok(i32::try_from(&invoke(
            control,
            "Connected",
            DISPATCH_PROPERTYGET,
            vec![],
        )?)?)
    }

    pub fn disconnect_reason(&self) -> Result<i32> {
        let control = self.control.as_ref().context("Windows RDP control is closed")?;
        Ok(i32::try_from(&invoke(
            control, "ExtendedDisconnectReason", DISPATCH_PROPERTYGET, vec![],
        )?)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    #[ignore = "Requires Windows ATL and installed Microsoft RDP ActiveX control; creates hidden local windows only"]
    fn embedded_control_configures_without_network_or_external_process() {
        let parent = unsafe {
            CreateWindowExW(
                WINDOW_EX_STYLE::default(),
                w!("STATIC"),
                w!("Relayne local host test"),
                Default::default(),
                0,
                0,
                640,
                480,
                None,
                None,
                None,
                None,
            )
        }
        .unwrap();
        let result = (|| -> Result<()> {
            let host = NativeRemoteApp::new(parent.0 as isize)?;
            let profile =
                crate::models::ConnectionProfile::sample("Local smoke", "localhost", "test", false);
            host.configure(
                &profile,
                &crate::remoteapp::RemoteAppOptions {
                    program: "||calc".into(),
                    ..Default::default()
                },
            )?;
            host.place(0, 0, 320, 240, false)?;
            assert_eq!(host.state()?, 0);
            let mut desktop = profile.clone();
            desktop.options.mstsc.set("redirectprinters", 1)?;
            desktop.options.mstsc.set("redirectsmartcards", 1)?;
            desktop.options.mstsc.set("redirectcomports", 1)?;
            desktop.options.mstsc.set("audiomode", 1)?;
            desktop.options.mstsc.set("keyboardhook", 1)?;
            desktop.options.mstsc.set("use multimon", 1)?;
            desktop.options.mstsc.drives = "C:;".into();
            desktop.options.gateway.enabled = true;
            desktop.options.gateway.host = "gateway.example".into();
            host.configure(&desktop, &Default::default())?;
            let control = host.control.as_ref().unwrap();
            assert_eq!(
                i32::try_from(&invoke(
                    control,
                    "ColorDepth",
                    DISPATCH_PROPERTYGET,
                    vec![]
                )?)?,
                32
            );
            let advanced = child(control, "AdvancedSettings9")?;
            assert_eq!(
                u32::try_from(&invoke(
                    &advanced,
                    "AudioRedirectionMode",
                    DISPATCH_PROPERTYGET,
                    vec![]
                )?)?,
                1
            );
            assert!(bool::try_from(&invoke(
                &advanced,
                "RedirectPrinters",
                DISPATCH_PROPERTYGET,
                vec![]
            )?)?);
            crate::native_rdp_resources::verify_resources(control, &desktop.options.mstsc)?;
            desktop
                .options
                .shared_folders
                .push(crate::connection_options::SharedFolder {
                    name: "restricted".into(),
                    path: "C:\\private".into(),
                    read_only: true,
                });
            assert!(
                host.configure(&desktop, &Default::default())
                    .unwrap_err()
                    .to_string()
                    .contains("read-only")
            );
            Ok(())
        })();
        unsafe {
            let _ = DestroyWindow(parent);
        }
        result.unwrap();
    }
}
impl Drop for NativeRemoteApp {
    fn drop(&mut self) {
        if let Some(control) = self.control.take() {
            let _ = invoke(&control, "Disconnect", DISPATCH_METHOD, vec![]);
            drop(control);
        }
        unsafe {
            let _ = DestroyWindow(self.window);
            OleUninitialize();
        }
    }
}
