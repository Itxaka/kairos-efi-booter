#![no_main]
#![no_std]


use log::info;
use uefi::prelude::*;
use uefi::CStr16;
use uefi::runtime::{self, get_variable, VariableAttributes, VariableVendor};


// Embedded keys
const PK: &[u8] = include_bytes!("../keys/pk.auth");
const KEK: &[u8] = include_bytes!("../keys/kek.auth");
const DB: &[u8] = include_bytes!("../keys/db.auth");



#[entry]
fn main() -> Status {
    uefi::helpers::init().unwrap();
    info!("Hello world!");

    log_secureboot_status();


    info!("Enrolling Secure Boot keys...");

    match enroll_key("PK", PK) {
        Ok(_) => info!("PK enrolled successfully."),
        Err(e) => info!("Failed to enroll PK: {:?}", e),
    }
    match enroll_key("KEK", KEK) {
        Ok(_) => info!("KEK enrolled successfully."),
        Err(e) => info!("Failed to enroll KEK: {:?}", e),
    }
    match enroll_key("db", DB) {
        Ok(_) => info!("DB enrolled successfully."),
        Err(e) => info!("Failed to enroll DB: {:?}", e),
    }
    
    boot::stall(10_000_000);
    Status::SUCCESS
}

fn log_secureboot_status() {
    let mut name_buf = [0u16; 16];
    let name = CStr16::from_str_with_buf("SecureBoot", &mut name_buf).unwrap();

    let mut buffer = [0u8; 4]; // SecureBoot is 1 byte, 0 or 1

    match get_variable(name, &VariableVendor::GLOBAL_VARIABLE, &mut buffer) {
        Ok((data, _attrs)) => {
            if data.len() == 1 {
                match data[0] {
                    0 => info!("SecureBoot: DISABLED (Setup Mode)"),
                    1 => info!("SecureBoot: ENABLED"),
                    other => info!("SecureBoot: UNKNOWN VALUE: {}", other),
                }
            } else {
                info!("SecureBoot var had unexpected length: {:?}", data);
            }
        }
        Err(e) => {
            if e.status() == Status::NOT_FOUND {
                info!("SecureBoot variable not found (Setup Mode or unset)");
            } else {
                info!("Failed to get SecureBoot variable: {:?}", e.status());
            }
        }
    }
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