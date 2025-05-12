#![no_main]
#![no_std]
extern crate alloc;
#[global_allocator]
static ALLOCATOR: uefi::allocator::Allocator = uefi::allocator::Allocator;

use alloc::format;
use alloc::string::ToString;
use alloc::vec::Vec;
use log::info;
use uefi::prelude::*;
use uefi::CStr16;
use uefi::runtime::{self, ResetType, VariableAttributes, VariableVendor};
use uefi::{Status};

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
            info!("Keys enrolled. Creating entry...");
            if let Err(e) = add_ipv4_efi_entry() {
                info!("Failed to add IPv4 EFI entry: {:?}", e);
            } else {
                info!("IPv4 EFI entry added successfully.");
            }
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

fn add_ipv4_efi_entry() -> Result<(), Status> {
    // Boot entry number we'll use (8)
    let boot_num: u16 = 8;
    let mut name_buf = [0u16; 16];
    let name = CStr16::from_str_with_buf(&format!("Boot{:04X}", boot_num), &mut name_buf).unwrap();

    info!("Creating boot entry: Boot{:04X} ({})", boot_num, boot_num);
    
    let boot_option_data = create_ipv4_boot_option_data("http://192.168.122.1/kairos.efi")?;
    let attributes = VariableAttributes::NON_VOLATILE | VariableAttributes::BOOTSERVICE_ACCESS 
               | VariableAttributes::RUNTIME_ACCESS;

    info!("Adding IPv4 EFI boot entry...");

    // Set the boot entry variable
    runtime::set_variable(
        name,
        &VariableVendor::GLOBAL_VARIABLE,
        attributes,
        &boot_option_data,
    ).map_err(|e| e.status())?;

    info!("Boot entry created, now updating BootOrder");
    
    // Get the current BootOrder
    let mut boot_order_buf = [0u8; 256]; // Should be enough for most systems
    let boot_order = get_boot_order(&mut boot_order_buf).unwrap_or_else(|e| {
        info!("Failed to get current BootOrder: {:?}, creating new one", e);
        &[][..]
    });
    
    // Print the current boot order
    if !boot_order.is_empty() {
        info!("Current boot order: {:04X?}", boot_order);
    } else {
        info!("No existing boot order found");
    }
    
    // Create new boot order with our entry at the beginning
    let mut new_boot_order = Vec::new();
    new_boot_order.push(boot_num);
    for &entry in boot_order {
        if entry != boot_num {
            new_boot_order.push(entry);
        }
    }
    
    info!("New boot order: {:04X?}", new_boot_order);
    
    // Update the BootOrder variable
    let mut boot_order_name_buf = [0u16; 16];
    let boot_order_name = CStr16::from_str_with_buf("BootOrder", &mut boot_order_name_buf).unwrap();
    
    runtime::set_variable(
        boot_order_name,
        &VariableVendor::GLOBAL_VARIABLE,
        attributes,
        &boot_order_to_bytes(&new_boot_order),
    ).map_err(|e| {
        info!("Failed to update BootOrder: {:?}", e.status());
        e.status()
    })?;
    
    info!("BootOrder updated successfully");
    
    // Optionally set BootNext for immediate testing
    let mut boot_next_name_buf = [0u16; 16];
    let boot_next_name = CStr16::from_str_with_buf("BootNext", &mut boot_next_name_buf).unwrap();
    
    runtime::set_variable(
        boot_next_name,
        &VariableVendor::GLOBAL_VARIABLE,
        VariableAttributes::NON_VOLATILE | VariableAttributes::BOOTSERVICE_ACCESS,
        &boot_num.to_le_bytes(),
    ).map_err(|e| {
        info!("Failed to set BootNext (non-critical): {:?}", e.status());
        Status::SUCCESS // Ignore this error
    })?;
    
    info!("BootNext set for next boot: {:04X} ({})", boot_num, boot_num);
    Ok(())
}

// Helper to get the current BootOrder
fn get_boot_order(buffer: &mut [u8]) -> Result<&[u16], Status> {
    let mut name_buf = [0u16; 16];
    let name = CStr16::from_str_with_buf("BootOrder", &mut name_buf).unwrap();

    match runtime::get_variable(name, &VariableVendor::GLOBAL_VARIABLE, buffer) {
        Ok((data, _)) => {
            if data.len() % 2 != 0 {
                return Err(Status::INVALID_PARAMETER);
            }
            
            // Safely convert bytes to u16 slice
            let u16_count = data.len() / 2;
            let boot_entries = unsafe {
                core::slice::from_raw_parts(data.as_ptr().cast::<u16>(), u16_count)
            };
            
            Ok(boot_entries)
        },
        Err(e) => Err(e.status()),
    }
}

// Convert Vec<u16> to bytes for storage
fn boot_order_to_bytes(boot_order: &[u16]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(boot_order.len() * 2);
    for &entry in boot_order {
        bytes.extend_from_slice(&entry.to_le_bytes());
    }
    bytes
}

fn create_ipv4_boot_option_data(url: &str) -> Result<Vec<u8>, Status> {
    // Create the device path first
    let device_path = create_ipv4_device_path(url)?;
    
    // Load option attributes - LOAD_OPTION_ACTIVE
    let attributes: u32 = 0x00000001;
    
    // Description as UTF-16 with null terminator
    let description = "Kairos IPv4 Boot\0";
    let description_utf16: Vec<u16> = description.encode_utf16().collect();
    
    // File path list length
    let file_path_list_length = device_path.len() as u16;
    
    // Total size
    let mut data = Vec::new();
    
    // Add attributes (u32)
    data.extend_from_slice(&attributes.to_le_bytes());
    
    // Add file path list length (u16)
    data.extend_from_slice(&file_path_list_length.to_le_bytes());
    
    // Add description (array of u16)
    for ch in &description_utf16 {
        data.extend_from_slice(&ch.to_le_bytes());
    }
    
    // Add device path
    data.extend_from_slice(&device_path);
    
    // No optional data
    
    info!("Created EFI_LOAD_OPTION: len={}, attributes={:#x}, file_path_len={}", 
          data.len(), attributes, file_path_list_length);
    
    Ok(data)
}

fn create_ipv4_device_path(url: &str) -> Result<Vec<u8>, Status> {
    let mut data = Vec::new();
    
    // Parse the server IP and path from the URL
    let url_parts: Vec<&str> = url.split('/').collect();
    let server_str = url_parts.get(2).ok_or(Status::INVALID_PARAMETER)?;
    let server_ip_str = server_str.split(':').next().unwrap_or(server_str);
    
    // Parse IP address
    let ip_parts: Vec<&str> = server_ip_str.split('.').collect();
    if ip_parts.len() != 4 {
        return Err(Status::INVALID_PARAMETER);
    }
    
    let remote_ip = [
        ip_parts[0].parse::<u8>().map_err(|_| Status::INVALID_PARAMETER)?,
        ip_parts[1].parse::<u8>().map_err(|_| Status::INVALID_PARAMETER)?,
        ip_parts[2].parse::<u8>().map_err(|_| Status::INVALID_PARAMETER)?,
        ip_parts[3].parse::<u8>().map_err(|_| Status::INVALID_PARAMETER)?
    ];
    
    // Get the file path part (everything after the server part)
    let file_path = if url_parts.len() > 3 {
        format!("/{}", url_parts[3..].join("/"))
    } else {
        "/".to_string()
    };
    
    info!("Parsed server IP: {}.{}.{}.{}, file path: {}", 
          remote_ip[0], remote_ip[1], remote_ip[2], remote_ip[3], file_path);

    // IPv4 node configured for HTTP
    data.push(0x03); // Type: Messaging Device Path
    data.push(0x0C); // Subtype: IPv4
    data.extend_from_slice(&[0x1B, 0x00]); // Length: 27 bytes
    data.extend_from_slice(&[0, 0, 0, 0]); // Local IP (0.0.0.0 for DHCP)
    data.extend_from_slice(&remote_ip);     // Remote IP
    data.extend_from_slice(&[0x00, 0x00]);  // Local port (0)
    data.extend_from_slice(&[0x00, 0x50]);  // Remote port (80 - HTTP)
    data.extend_from_slice(&[0x06, 0x00]);  // Protocol (TCP - 6)
    data.push(0x00);                        // IP address origin (0 = DHCP)
    data.extend_from_slice(&[0, 0, 0, 0]);  // Gateway IP
    data.extend_from_slice(&[0, 0, 0, 0]);  // Subnet mask

    // Add a file path node to specify the path on the HTTP server
    let file_path_utf16: Vec<u16> = file_path.encode_utf16().chain(Some(0)).collect();
    data.push(0x04);  // Type: Media Device Path
    data.push(0x04);  // Subtype: File Path
    let path_len = (file_path_utf16.len() * 2 + 4) as u16;  // Length: 4 bytes header + path length in bytes
    data.extend_from_slice(&path_len.to_le_bytes());
    
    // Add the file path as UTF-16
    for c in file_path_utf16 {
        data.extend_from_slice(&c.to_le_bytes());
    }
    
    // End node
    data.push(0x7F); // Type: End of Hardware Device Path
    data.push(0xFF); // Subtype: End Entire Device Path
    data.extend_from_slice(&[0x04, 0x00]); // Length: 4 bytes
    
    info!("Created HTTP boot device path with {} bytes", data.len());
    
    Ok(data)
}

