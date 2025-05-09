#![no_main]
#![no_std]
extern crate alloc;
#[global_allocator]
static ALLOCATOR: uefi::allocator::Allocator = uefi::allocator::Allocator;

use log::info;
use uefi::prelude::*;
use uefi::CStr16;
use uefi::runtime::{self, ResetType, VariableAttributes, VariableVendor};
use uefi::{
    Status,
};


// Embedded keys
const PK: &[u8] = include_bytes!("../keys/PK.auth");
const KEK: &[u8] = include_bytes!("../keys/KEK.auth");
const DB: &[u8] = include_bytes!("../keys/DB.auth");



#[entry]
fn main() -> Status {
    uefi::helpers::init().unwrap();
    info!("Booting key enroller...");

    if is_setup_mode() {
        info!("Setup Mode detected. Enrolling keys...");
        if let Err(e) = enroll_all_keys() {
            info!("Key enrollment failed: {:?}", e);
        } else {
            info!("Keys enrolled. entry created. Rebooting...");
            runtime::reset(ResetType::COLD, Status::SUCCESS, None);
        }
    } else {
    }

    boot::stall(5_000_000);
    Status::SUCCESS
}


fn is_setup_mode() -> bool {
    let mut name_buf = [0u16; 16];
    let name = CStr16::from_str_with_buf("SetupMode", &mut name_buf).unwrap();
    let mut buffer = [0u8; 1];

    match runtime::get_variable(name, &VariableVendor::GLOBAL_VARIABLE, &mut buffer) {
        Ok((data, _)) => data.len() == 1 && data[0] == 1,
        _ => false,
    }
}

fn enroll_all_keys() -> Result<(), uefi::Status> {
    enroll_key("PK", PK)?;
    enroll_key("KEK", KEK)?;
    enroll_key("db", DB)?;
    Ok(())
}

fn enroll_key(name: &str, data: &[u8]) -> Result<(), Status> {
    let mut binding = [0u16; 16];
    let name_utf16 = CStr16::from_str_with_buf(name, &mut binding).unwrap();

    let vendor = match name {
        "db" | "dbx" => &VariableVendor::IMAGE_SECURITY_DATABASE,
        "PK" | "KEK" => &VariableVendor::GLOBAL_VARIABLE,
        _ => return Err(Status::INVALID_PARAMETER),
    };

    info!("Setting var '{}', vendor: {:?}, size: {}", name, vendor, data.len());
    runtime::set_variable(
        name_utf16,
        vendor,
        VariableAttributes::NON_VOLATILE
            | VariableAttributes::BOOTSERVICE_ACCESS
            | VariableAttributes::RUNTIME_ACCESS
            | VariableAttributes::TIME_BASED_AUTHENTICATED_WRITE_ACCESS,
        data,
    ).map_err(|e| e.status())
}