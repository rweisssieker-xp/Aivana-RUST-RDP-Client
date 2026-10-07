//! Narrow bindings for the documented, non-scriptable MSTSC resource interfaces.
//! These interfaces derive from IUnknown, not IDispatch. Layout follows mstscax.idl:
//! IMsTscNonScriptable -> IMsRdpClientNonScriptable[2,3,4,5]. Reserved slots are
//! methods we never invoke. All calls stay on the ActiveX host's UI STA thread.
use anyhow::{Context, Result};
use std::ffi::c_void;
use windows::Win32::System::Com::IDispatch;
use windows::core::{BSTR, HRESULT, IUnknown_Vtbl, Interface};

type BoolPut = unsafe extern "system" fn(*mut c_void, i16) -> HRESULT;
type BoolGet = unsafe extern "system" fn(*mut c_void, *mut i16) -> HRESULT;
type ObjectGet = unsafe extern "system" fn(*mut c_void, *mut *mut c_void) -> HRESULT;
type ItemGet = unsafe extern "system" fn(*mut c_void, u32, *mut *mut c_void) -> HRESULT;
type CountGet = unsafe extern "system" fn(*mut c_void, *mut u32) -> HRESULT;
type StringGet = unsafe extern "system" fn(*mut c_void, *mut BSTR) -> HRESULT;

windows::core::imp::define_interface!(
    NonScriptable5,
    NonScriptable5Vtbl,
    0x4f6996d5_d7b1_412c_b0ff_063718566907
);
#[repr(C)]
pub struct NonScriptable5Vtbl {
    base: IUnknown_Vtbl, // slots 0..2
    password: unsafe extern "system" fn(*mut c_void, *const u16) -> HRESULT, // 3
    reserved_4_24: [usize; 21],
    dynamic_drives: BoolPut, // 25
    reserved_26: usize,
    dynamic_devices: BoolPut, // 27
    reserved_28: usize,
    devices: ObjectGet, // 29
    drives: ObjectGet,  // 30
    reserved_31_52: [usize; 22],
    multimon: BoolPut,     // 53
    get_multimon: BoolGet, // 54
    reserved_55_62: [usize; 8],
    allow_prompting: BoolPut, // 63
    get_allow_prompting: BoolGet, // 64
}
windows::core::imp::define_interface!(
    DriveCollection,
    DriveCollectionVtbl,
    0x7ff17599_da2c_4677_ad35_f60c04fe1585
);
#[repr(C)]
pub struct DriveCollectionVtbl {
    base: IUnknown_Vtbl,
    rescan: BoolPut,
    item: ItemGet,
    count: CountGet,
}
windows::core::imp::define_interface!(Drive, DriveVtbl, 0xd28b5458_f694_47a8_8e61_40356a767e46);
#[repr(C)]
pub struct DriveVtbl {
    base: IUnknown_Vtbl,
    name: StringGet,
    redirect: BoolPut,
    get_redirect: BoolGet,
}
windows::core::imp::define_interface!(
    DeviceCollection,
    DeviceCollectionVtbl,
    0x56540617_d281_488c_8738_6a8fdf64a118
);
#[repr(C)]
pub struct DeviceCollectionVtbl {
    base: IUnknown_Vtbl,
    rescan: BoolPut,
    item: ItemGet,
    by_id: usize,
    count: CountGet,
}
windows::core::imp::define_interface!(Device, DeviceVtbl, 0x60c3b9c8_9e92_4f5e_a3e7_604a912093ea);
#[repr(C)]
pub struct DeviceVtbl {
    base: IUnknown_Vtbl,
    id: StringGet,
    name: StringGet,
    description: StringGet,
    redirect: BoolPut,
    get_redirect: BoolGet,
}

fn vb(value: bool) -> i16 {
    if value { -1 } else { 0 }
}
fn selected_drive(list: &str, name: &str) -> bool {
    list.split(';').any(|part| {
        part == "*"
            || (!part.is_empty() && part.eq_ignore_ascii_case(name.trim_end_matches(['\\', '/'])))
    })
}

pub fn configure(control: &IDispatch, profile: &crate::models::ConnectionProfile) -> Result<()> {
    let options = &profile.options.mstsc;
    options.validate()?;
    let ns: NonScriptable5 = control
        .cast()
        .context("Windows RDP resource interface unavailable")?;
    // Every returned interface owns one COM reference, released by its wrapper.
    // The queried IID guarantees the documented vtable layout above.
    unsafe {
        let vt = ns.vtable();
        let raw = ns.as_raw();
        let password = BSTR::from(profile.password.as_str());
        (vt.password)(raw, password.as_ptr())
            .ok()
            .context("Set RDP credentials")?;
        // Permit Windows to recover from missing or rejected saved credentials.
        // IMsRdpClientNonScriptable5::AllowPromptingForCredentials.
        (vt.allow_prompting)(raw, vb(true))
            .ok()
            .context("Enable Windows credential prompt")?;
        (vt.multimon)(raw, vb(options.get("use multimon") == 1))
            .ok()
            .context("Configure multiple monitors")?;
        let dynamic_drives = options
            .drives
            .split(';')
            .any(|s| s == "DynamicDrives" || s == "*");
        (vt.dynamic_drives)(raw, vb(dynamic_drives)).ok()?;
        (vt.dynamic_devices)(
            raw,
            vb(options.devices == "DynamicDevices" || options.devices == "*"),
        )
        .ok()?;

        let mut collection = std::ptr::null_mut();
        (vt.drives)(raw, &mut collection)
            .ok()
            .context("Read local drives")?;
        anyhow::ensure!(
            !collection.is_null(),
            "Windows returned no drive collection"
        );
        let drives = DriveCollection::from_raw(collection);
        (drives.vtable().rescan)(drives.as_raw(), vb(dynamic_drives)).ok()?;
        let mut count = 0;
        (drives.vtable().count)(drives.as_raw(), &mut count).ok()?;
        for index in 0..count {
            let mut item = std::ptr::null_mut();
            (drives.vtable().item)(drives.as_raw(), index, &mut item).ok()?;
            anyhow::ensure!(!item.is_null(), "Windows returned no drive");
            let drive = Drive::from_raw(item);
            let mut name = BSTR::default();
            (drive.vtable().name)(drive.as_raw(), &mut name).ok()?;
            (drive.vtable().redirect)(
                drive.as_raw(),
                vb(selected_drive(&options.drives, &name.to_string())),
            )
            .ok()?;
        }

        let mut collection = std::ptr::null_mut();
        (vt.devices)(raw, &mut collection)
            .ok()
            .context("Read supported local devices")?;
        anyhow::ensure!(
            !collection.is_null(),
            "Windows returned no device collection"
        );
        let devices = DeviceCollection::from_raw(collection);
        (devices.vtable().rescan)(devices.as_raw(), vb(options.devices == "DynamicDevices"))
            .ok()?;
        let mut count = 0;
        (devices.vtable().count)(devices.as_raw(), &mut count).ok()?;
        for index in 0..count {
            let mut item = std::ptr::null_mut();
            (devices.vtable().item)(devices.as_raw(), index, &mut item).ok()?;
            anyhow::ensure!(!item.is_null(), "Windows returned no device");
            let device = Device::from_raw(item);
            (device.vtable().redirect)(device.as_raw(), vb(options.devices == "*")).ok()?;
        }
    }
    Ok(())
}

#[cfg(test)]
pub fn verify_resources(
    control: &IDispatch,
    settings: &crate::mstsc_settings::MstscSettings,
) -> Result<()> {
    let ns: NonScriptable5 = control.cast()?;
    unsafe {
        let mut multi = 0;
        let mut prompting = 0;
        (ns.vtable().get_allow_prompting)(ns.as_raw(), &mut prompting).ok()?;
        anyhow::ensure!(prompting != 0, "Windows credential prompting is disabled");
        (ns.vtable().get_multimon)(ns.as_raw(), &mut multi).ok()?;
        anyhow::ensure!(
            (multi != 0) == (settings.get("use multimon") == 1),
            "Multimon setting did not reach Windows"
        );
        let mut raw = std::ptr::null_mut();
        (ns.vtable().drives)(ns.as_raw(), &mut raw).ok()?;
        anyhow::ensure!(!raw.is_null(), "Missing drive collection");
        let drives = DriveCollection::from_raw(raw);
        let mut count = 0;
        (drives.vtable().count)(drives.as_raw(), &mut count).ok()?;
        for index in 0..count {
            let mut item = std::ptr::null_mut();
            (drives.vtable().item)(drives.as_raw(), index, &mut item).ok()?;
            anyhow::ensure!(!item.is_null(), "Missing drive");
            let drive = Drive::from_raw(item);
            let mut name = BSTR::default();
            let mut redirected = 0;
            (drive.vtable().name)(drive.as_raw(), &mut name).ok()?;
            (drive.vtable().get_redirect)(drive.as_raw(), &mut redirected).ok()?;
            anyhow::ensure!(
                (redirected != 0) == selected_drive(&settings.drives, &name.to_string()),
                "Drive selection did not reach Windows"
            );
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn drive_selection_is_exact_and_case_insensitive() {
        assert!(selected_drive("C:;D:;", "c:\\"));
        assert!(!selected_drive("C:;D:;", "E:\\"));
        assert!(!selected_drive("DynamicDrives", "C:\\"));
        assert!(selected_drive("*", "E:\\"));
    }
    #[test]
    fn resource_interface_offsets_match_mstscax_abi() {
        let p = std::mem::size_of::<usize>();
        assert_eq!(std::mem::offset_of!(NonScriptable5Vtbl, multimon), 53 * p);
        assert_eq!(std::mem::offset_of!(NonScriptable5Vtbl, drives), 30 * p);
        assert_eq!(std::mem::offset_of!(DeviceVtbl, redirect), 6 * p);
    }
}
