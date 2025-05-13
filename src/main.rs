#![no_main]
#![no_std]
extern crate alloc;
#[global_allocator]
static ALLOCATOR: uefi::allocator::Allocator = uefi::allocator::Allocator;

use alloc::format;
use log::info;
use uefi::prelude::*;
use uefi::CStr16;
use uefi::runtime::{self, ResetType, VariableAttributes, VariableVendor};
use uefi::Status;
use alloc::vec::Vec;
use uefi::boot;
use uefi::proto::network::ip4config2::Ip4Config2;

const KEY_SERVER: &str = "http://192.168.122.1/";

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
    let pk_url = format!("{}PK.auth", KEY_SERVER);
    let kek_url = format!("{}KEK.auth", KEY_SERVER);
    let db_url = format!("{}DB.auth", KEY_SERVER);

    info!("Downloading PK...");
    let pk = http_download(&pk_url)?;
    info!("Downloading KEK...");
    let kek = http_download(&kek_url)?;
    info!("Downloading db...");
    let db = http_download(&db_url)?;

    enroll_key("PK", &pk)?;
    enroll_key("KEK", &kek)?;
    enroll_key("db", &db)?;
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

fn http_download(url: &str) -> Result<Vec<u8>, Status> {
    let nic_handle = boot::get_handle_for_protocol::<uefi::proto::network::http::HttpBinding>()
        .map_err(|e| e.status())?;

    // Bring up the network interface (DHCP)
    {
        let mut ip4 = Ip4Config2::new(nic_handle)
            .map_err(|e| e.status())?;
        ip4.ifup(false).map_err(|e| e.status())?;

        // Print IP configuration after DHCP
        if let Ok(info) = ip4.get_interface_info() {
            let hw = &info.hw_addr;
            log::info!(
                "IP config: addr {}.{}.{}.{}, mask {}.{}.{}.{}, hw_addr {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                info.station_addr.0[0], info.station_addr.0[1], info.station_addr.0[2], info.station_addr.0[3],
                info.subnet_mask.0[0], info.subnet_mask.0[1], info.subnet_mask.0[2], info.subnet_mask.0[3],
                hw.0[0], hw.0[1], hw.0[2], hw.0[3], hw.0[4], hw.0[5]
            );
        }
    }

    let mut http = uefi::proto::network::http::HttpHelper::new(nic_handle)
        .map_err(|e| e.status())?;
    http.configure().map_err(|e| e.status())?;
    http.request_get(url).map_err(|e| e.status())?;
    let resp = http.response_first(true).map_err(|e| e.status())?;
    Ok(resp.body)
}

