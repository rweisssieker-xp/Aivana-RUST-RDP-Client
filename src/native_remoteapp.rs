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
        crate::remoteapp::rdp_document(profile, app)?; // Validate all externally supplied values.
        if profile.options.gateway.enabled && profile.options.gateway.paa {
            bail!(
                "PAA cookies use the native IronRDP gateway connection; the ActiveX host does not support passing them through"
            );
        }
        if !app.working_directory.is_empty() {
            bail!("A working directory is not yet supported for embedded RemoteApps");
        }
        let control = self
            .control
            .as_ref()
            .context("RemoteApp control is closed")?;
        put(control, "Server", profile.host.as_str())?;
        put(control, "UserName", profile.username.as_str())?;
        put(control, "Domain", profile.domain.as_str())?;
        let advanced = child(control, "AdvancedSettings7")?;
        put(&advanced, "RDPPort", i32::from(profile.port))?;
        put(&advanced, "AuthenticationLevel", 1u32)?;
        put(&advanced, "EnableCredSspSupport", true)?;
        put(&advanced, "RedirectClipboard", false)?;
        put(&advanced, "RedirectDrives", false)?;
        put(&advanced, "RedirectPrinters", false)?;
        let remote = child(control, "RemoteProgram2")?;
        put(&remote, "RemoteProgramMode", true)?;
        put(&remote, "RemoteApplicationProgram", app.program.as_str())?;
        put(&remote, "RemoteApplicationName", app.name.as_str())?;
        put(&remote, "RemoteApplicationArgs", app.arguments.as_str())?;
        let gateway = &profile.options.gateway;
        if gateway.enabled {
            let transport = child(control, "TransportSettings2")?;
            put(
                &transport,
                "GatewayHostname",
                format!("{}:{}", gateway.host, gateway.port).as_str(),
            )?;
            put(&transport, "GatewayUsageMethod", 1u32)?;
            put(&transport, "GatewayProfileUsageMethod", 1u32)?;
            put(&transport, "GatewayCredsSource", 0u32)?;
        }
        Ok(())
    }

    /// Physical pixels relative to the parent HWND client area; hide inactive tabs.
    pub fn place(&self, x: i32, y: i32, width: i32, height: i32, visible: bool) -> Result<()> {
        unsafe {
            MoveWindow(self.window, x, y, width.max(1), height.max(1), true)?;
            let _ = ShowWindow(self.window, if visible { SW_SHOW } else { SW_HIDE });
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
