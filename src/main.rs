#![no_main]
#![no_std]
extern crate alloc;
#[global_allocator]
static ALLOCATOR: uefi::allocator::Allocator = uefi::allocator::Allocator;

use alloc::format;
use alloc::string::{String, ToString};
use log::{info, LevelFilter};
use uefi::prelude::*;
use uefi::CStr16;
use uefi::runtime::{self, ResetType, VariableAttributes, VariableVendor};
use uefi::Status;
use alloc::vec::Vec;
use uefi::boot;
use uefi::proto::network::ip4config2::Ip4Config2;
use uefi::proto::network::pxe::{BaseCode, DhcpV4Packet};


#[entry]
fn main() -> Status {
    uefi::helpers::init().unwrap();
    
    // Set the log level to only show INFO logs and above (suppress DEBUG logs)
    log::set_max_level(LevelFilter::Info);

    info!("Booting key enroller...");

    // Setup network interface once
    if let Err(e) = setup_network_interface() {
        info!("Failed to setup network interface: {:?}", e);
        boot::stall(5_000_000);
        runtime::reset(ResetType::COLD, Status::ABORTED, None);
    }

    // Try to request DHCP information to find PXE server info
    let server = match request_dhcp_info() {
        Some(server) => {
            info!("Next boot server (from DHCP): {}", server);
            server
        },
        None => {
            info!("No next boot server found in DHCP options, cant continue!");
            boot::stall(5_000_000);
            runtime::reset(ResetType::COLD, Status::ABORTED, None);
        },
    };

    if is_setup_mode() {
        info!("Setup Mode detected. Enrolling keys...");
        if let Err(e) = enroll_all_keys(&server) {
            info!("Key enrollment failed: {:?}", e);
        } else {
            info!("Keys enrolled. entry created. Rebooting...");
            runtime::reset(ResetType::COLD, Status::SUCCESS, None);
        }
    } else {
        info!("Not in setup mode, skipping key enrollment");
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

fn enroll_all_keys(server: &str) -> Result<(), Status> {
    let base_url = format!("http://{}/", server);
    let pk_url = format!("{}PK.auth", base_url);
    let kek_url = format!("{}KEK.auth", base_url);
    let db_url = format!("{}DB.auth", base_url);

    info!("Downloading PK from {}...", pk_url);
    let pk = match http_download(&pk_url) {
        Ok(data) => data,
        Err(e) => {
            info!("Failed to download PK: {:?}. Stalling for 5 seconds before reset.", e);
            boot::stall(5_000_000);
            runtime::reset(ResetType::COLD, Status::ABORTED, None);
        }
    };
    info!("Downloading KEK from {}...", kek_url);
    let kek = match http_download(&kek_url) {
        Ok(data) => data,
        Err(e) => {
            info!("Failed to download KEK: {:?}. Stalling for 5 seconds before reset.", e);
            boot::stall(5_000_000);
            runtime::reset(ResetType::COLD, Status::ABORTED, None);
        }
    };
    info!("Downloading db from {}...", db_url);
    let db = match http_download(&db_url) {
        Ok(data) => data,
        Err(e) => {
            info!("Failed to download DB: {:?}. Stalling for 5 seconds before reset.", e);
            boot::stall(5_000_000);
            runtime::reset(ResetType::COLD, Status::ABORTED, None);
        }
    };

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
    
    // Log the first few and last few bytes of the data for debugging
    if !data.is_empty() {
        let prefix_len = core::cmp::min(16, data.len());
        let suffix_start = if data.len() > 16 { data.len() - 16 } else { 0 };
        
        let mut prefix_str = String::new();
        for byte in &data[0..prefix_len] {
            prefix_str.push_str(&format!("{:02x} ", byte));
        }
        
        let mut suffix_str = String::new();
        if data.len() > 16 {
            suffix_str.push_str("... ");
            for byte in &data[suffix_start..] {
                suffix_str.push_str(&format!("{:02x} ", byte));
            }
        }
    }
    
    let result = runtime::set_variable(
        name_utf16,
        vendor,
        VariableAttributes::NON_VOLATILE
            | VariableAttributes::BOOTSERVICE_ACCESS
            | VariableAttributes::RUNTIME_ACCESS
            | VariableAttributes::TIME_BASED_AUTHENTICATED_WRITE_ACCESS,
        data,
    );
    
    if let Err(ref e) = result {
        info!("set_variable for '{}' failed with status: {:?}", name, e.status());
    }
    
    result.map_err(|e| e.status())
}

fn setup_network_interface() -> Result<(), Status> {
    info!("Setting up network interface...");
    let nic_handle = boot::get_handle_for_protocol::<uefi::proto::network::http::HttpBinding>()
        .map_err(|e| e.status())?;

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
    Ok(())
}

fn http_download(url: &str) -> Result<Vec<u8>, Status> {
    info!("Starting HTTP download from {}", url);
    let nic_handle = boot::get_handle_for_protocol::<uefi::proto::network::http::HttpBinding>()
        .map_err(|e| e.status())?;

    let mut http = uefi::proto::network::http::HttpHelper::new(nic_handle)
        .map_err(|e| e.status())?;
    http.configure().map_err(|e| e.status())?;
    
    // Send the HTTP GET request
    http.request_get(url).map_err(|e| e.status())?;
    
    // Get the first part of the response (includes headers and initial body chunk)
    let resp = http.response_first(true).map_err(|e| {
        info!("HTTP response_first failed: {:?}", e);
        e.status()
    })?;

    // Check HTTP status code (3 is STATUS_200_OK in the HttpStatusCode enum)
    if resp.status.0 != 3 { // STATUS_200_OK
        info!("HTTP GET failed: non-success status code {:?}", resp.status);
        return Err(Status::PROTOCOL_ERROR);
    }

    // Log headers and look for Content-Length
    let mut content_length: Option<usize> = None;
    for (name, value) in &resp.headers {
        info!("  {}: {}", name, value);
        if name.to_lowercase() == "content-length" {
            if let Ok(len) = value.parse::<usize>() {
                content_length = Some(len);
                info!("Found Content-Length: {} bytes", len);
            }
        }
    }

    // Start with the initial body chunk
    let mut full_body = resp.body;
    
    // Try to get more data until we have the complete file or no more data is available
    let mut chunk_count = 1;
    loop {
        // Try to get more body data
        match http.response_more() {
            Ok(more_data) => {
                if more_data.is_empty() {
                    break;
                }
                
                chunk_count += 1;
                full_body.extend_from_slice(&more_data);
                
                // Log progress if Content-Length is known
                if let Some(total) = content_length {
                    info!("Progress: {}/{} bytes ({:.1}%)", 
                          full_body.len(), total, 
                          (full_body.len() as f32 / total as f32) * 100.0);
                    
                    // If we've received all the data, we're done
                    if full_body.len() >= total {
                        info!("Download complete, received all {} bytes", full_body.len());
                        break;
                    }
                }
            },
            Err(e) => {
                // NOT_FOUND typically means no more data is available
                if e.status() == Status::NOT_FOUND {
                    info!("No more data available");
                } else {
                    info!("Error fetching additional data: {:?}", e);
                }
                break;
            }
        }
        
        // Safety check to prevent infinite loops
        if chunk_count > 50 {
            info!("Reached maximum chunk count, stopping download");
            break;
        }
    }
    
    if full_body.is_empty() {
        info!("HTTP GET succeeded but response body is empty");
        return Err(Status::NO_RESPONSE);
    }
    
    // Warn if download might be incomplete based on Content-Length
    if let Some(expected) = content_length {
        if full_body.len() < expected {
            info!("Warning: Incomplete download. Got {}/{} bytes", full_body.len(), expected);
        }
    }
    
    info!("HTTP download complete for {}. Total size: {} bytes in {} chunks", url, full_body.len(), chunk_count);
    
    Ok(full_body)
}

/// Sends a DHCP request to discover PXE server information and returns the next boot server address
/// from either Option 66 (TFTP server name) or the siaddr field in the DHCP header.
pub fn request_dhcp_info() -> Option<String> {
    info!("Sending DHCP discovery request to find PXE server...");
    
    // Try to find a network interface with the PXE Base Code protocol
    let nic_handle = match boot::get_handle_for_protocol::<BaseCode>() {
        Ok(handle) => {
            info!("Found NIC with PXE Base Code protocol: {:?}", handle);
            handle
        },
        Err(e) => {
            info!("No network interface with PXE Base Code protocol found: {:?}", e);
            return None;
        }
    };
    
    // Open the PXE protocol
    let mut pxe = match boot::open_protocol_exclusive::<BaseCode>(nic_handle) {
        Ok(p) => p,
        Err(e) => {
            info!("Failed to open PXE Base Code protocol: {:?}", e);
            return None;
        }
    };
    
    // Make sure the protocol is started
    if !pxe.mode().started() {
        info!("Starting PXE Base Code protocol");
        if let Err(e) = pxe.start(false) {
            info!("Failed to start PXE Base Code protocol: {:?}", e);
            return None;
        }
    }
    
    // Try to perform a DHCP discovery
    info!("Sending DHCP request...");
    if let Err(e) = pxe.dhcp(true) {
        info!("DHCP request failed: {:?}", e);
        return None;
    }
    
    // Successfully received DHCP response
    let mode = pxe.mode();
    
    if mode.dhcp_ack_received() {
        info!("Received DHCP ACK packet");
        let dhcp_packet = mode.dhcp_ack();
        let dhcp_v4 = AsRef::<DhcpV4Packet>::as_ref(dhcp_packet);
        
        // Log server information
        let server_addr = dhcp_v4.bootp_si_addr;
        info!("DHCP Server IP (siaddr): {}.{}.{}.{}", 
             server_addr[0], server_addr[1], 
             server_addr[2], server_addr[3]);
        
        let your_addr = dhcp_v4.bootp_yi_addr;
        info!("Your IP address: {}.{}.{}.{}", 
             your_addr[0], your_addr[1], 
             your_addr[2], your_addr[3]);
        
        // Check for Option 66 (TFTP Server Name) in DHCP options
        info!("Scanning DHCP options for Option 66 (TFTP server name)...");
        let dhcp_options = &dhcp_v4.dhcp_options;
        let mut i = 0;
        
        while i + 2 < dhcp_options.len() {
            let option_code = dhcp_options[i];
            if option_code == 255 { // End option
                break;
            }
            
            let option_len = dhcp_options[i+1] as usize;
            if i + 2 + option_len > dhcp_options.len() {
                break;
            }
            
            // Found Option 66 (TFTP Server Name)
            if option_code == 66 {
                if let Ok(server_name) = core::str::from_utf8(&dhcp_options[i+2..i+2+option_len]) {
                    info!("Found boot server name in Option 66: {}", server_name);
                    return Some(server_name.to_string());
                }
            }
            
            // Skip to next option
            i += option_len + 2;
        }
        
        // If Option 66 not found, use siaddr (next server IP) as the boot server
        if server_addr != [0, 0, 0, 0] {
            let ip = format!("{}.{}.{}.{}", 
                server_addr[0], server_addr[1], 
                server_addr[2], server_addr[3]);
            info!("Using DHCP server IP (siaddr) as boot server: {}", ip);
            return Some(ip);
        }
        
        // Check for PXE-specific information if siaddr is not set
        if mode.proxy_offer_received() {
            let proxy_offer = mode.proxy_offer();
            let proxy_v4 = AsRef::<DhcpV4Packet>::as_ref(proxy_offer);
            let proxy_addr = proxy_v4.bootp_si_addr;
            
            if proxy_addr != [0, 0, 0, 0] {
                let ip = format!("{}.{}.{}.{}", 
                    proxy_addr[0], proxy_addr[1], 
                    proxy_addr[2], proxy_addr[3]);
                info!("Using PXE Proxy Server as boot server: {}", ip);
                return Some(ip);
            }
        }
        
        if mode.pxe_reply_received() {
            let pxe_reply = mode.pxe_reply();
            let pxe_v4 = AsRef::<DhcpV4Packet>::as_ref(pxe_reply);
            let pxe_addr = pxe_v4.bootp_si_addr;
            
            if pxe_addr != [0, 0, 0, 0] {
                let ip = format!("{}.{}.{}.{}", 
                    pxe_addr[0], pxe_addr[1], 
                    pxe_addr[2], pxe_addr[3]);
                info!("Using PXE Reply Server as boot server: {}", ip);
                return Some(ip);
            }
        }
    } else {
        info!("No DHCP ACK received");
    }
    
    info!("Could not determine boot server from DHCP information");
    None
}
