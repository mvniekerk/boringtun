// Copyright (c) 2019 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use super::drop_privileges::get_saved_ids;
use super::{AllowedIP, Device, Error, SocketAddr};
use crate::serialization::KeyBytes;
use crate::x25519;
use hex::encode as encode_hex;
use libc::*;
use std::fs::{create_dir, remove_file};
use std::os::unix::io::FromRawFd;
use std::sync::Arc;
use std::time::Instant;
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncWrite, AsyncWriteExt, BufReader, BufWriter};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::RwLock;

const SOCK_DIR: &str = "/var/run/wireguard/";

fn create_sock_dir() {
    let _ = create_dir(SOCK_DIR); // Create the directory if it does not exist

    if let Ok((saved_uid, saved_gid)) = get_saved_ids() {
        unsafe {
            let c_path = std::ffi::CString::new(SOCK_DIR).unwrap();
            // The directory is under the root user, but we want to be able to
            // delete the files there when we exit, so we need to change the owner
            chown(
                c_path.as_bytes_with_nul().as_ptr() as _,
                saved_uid,
                saved_gid,
            );
        }
    }
}

impl Device {
    /// Register the api handler for this Device. The api handler receives stream connections on a Unix socket
    /// with a known path: /var/run/wireguard/{tun_name}.sock.
    pub fn register_api_handler(&mut self, device: Arc<RwLock<Device>>) -> Result<(), Error> {
        let path = format!("{}/{}.sock", SOCK_DIR, self.iface.name().unwrap());

        create_sock_dir();

        let _ = remove_file(&path); // Attempt to remove the socket if already exists

        let api_listener = UnixListener::bind(&path).map_err(Error::ApiSocket)?; // Bind a new socket to the path

        self.cleanup_paths.push(path);

        tokio::spawn(async move {
            loop {
                let (api_conn, _) = match api_listener.accept().await {
                    Ok(conn) => conn,
                    _ => return,
                };

                let d = device.clone();
                tokio::spawn(async move {
                    let (reader, writer) = api_conn.into_split();
                    let reader = BufReader::new(reader);
                    let mut reader = BufReader::new(reader);
                    let mut writer = BufWriter::new(writer);
                    let mut cmd = String::new();
                    if reader.read_line(&mut cmd).await.is_ok() {
                        cmd.pop(); // pop the new line character
                        let status = match cmd.as_ref() {
                            "get=1" => api_get(&mut writer, &*d.read().await).await,
                            "set=1" => api_set(&mut reader, &mut *d.write().await).await,
                            _ => EIO,
                        };
                        writer
                            .write_all(format!("errno={status}\n").as_bytes())
                            .await
                            .ok();
                        writer.flush().await.ok();
                    }
                });
            }
        });

        Ok(())
    }

    pub fn register_api_fd(&mut self, fd: i32, device: Arc<RwLock<Device>>) -> Result<(), Error> {
        let std_stream = unsafe { std::os::unix::net::UnixStream::from_raw_fd(fd) };
        std_stream.set_nonblocking(true).unwrap();
        let io_file = UnixStream::from_std(std_stream).unwrap();

        tokio::spawn(async move {
            let d = device.clone();
            let (reader, writer) = io_file.into_split();
            let reader = BufReader::new(reader);
            let mut reader = BufReader::new(reader);
            let mut writer = BufWriter::new(writer);
            loop {
                let mut cmd = String::new();
                if reader.read_line(&mut cmd).await.is_ok() {
                    cmd.pop(); // pop the new line character
                    let status = match cmd.as_ref() {
                        "get=1" => api_get(&mut writer, &*d.read().await).await,
                        "set=1" => api_set(&mut reader, &mut *d.write().await).await,
                        _ => EIO,
                    };
                    writer
                        .write_all(format!("errno={status}\n").as_bytes())
                        .await
                        .ok();
                    writer.flush().await.ok();
                } else {
                    return;
                }
            }
        });

        Ok(())
    }
}

#[allow(unused_must_use)]
async fn api_get<T: AsyncWrite + Unpin>(writer: &mut BufWriter<T>, d: &Device) -> i32 {
    if let Some(ref k) = d.key_pair {
        writer
            .write_all(format!("own_public_key={}\n", encode_hex(k.1.as_bytes())).as_bytes())
            .await
            .ok();
    }

    if d.listen_port != 0 {
        writer
            .write_all(format!("listen_port={}\n", d.listen_port).as_bytes())
            .await
            .ok();
    }

    if let Some(fwmark) = d.fwmark {
        writer
            .write_all(format!("fwmark={fwmark}\n").as_bytes())
            .await
            .ok();
    }

    for (k, p) in d.peers.iter() {
        let p = p.read().await;
        writer
            .write_all(format!("public_key={}\n", encode_hex(k.as_bytes())).as_bytes())
            .await
            .ok();

        if let Some(ref key) = p.preshared_key() {
            writer
                .write_all(format!("preshared_key={}\n", encode_hex(key)).as_bytes())
                .await
                .ok();
        }

        if let Some(keepalive) = p.persistent_keepalive() {
            writer
                .write_all(format!("persistent_keepalive_interval={keepalive}\n").as_bytes())
                .await
                .ok();
        }

        if let Some(ref addr) = p.endpoint().await.addr {
            writer
                .write_all(format!("endpoint={addr}\n").as_bytes())
                .await
                .ok();
        }

        for (ip, cidr) in p.allowed_ips() {
            writer
                .write_all(format!("allowed_ip={ip}/{cidr}\n").as_bytes())
                .await
                .ok();
        }

        if let Some(time) = p.time_since_last_handshake() {
            writer
                .write_all(format!("last_handshake_time_sec={}\n", time.as_secs()).as_bytes())
                .await
                .ok();
            writer
                .write_all(format!("last_handshake_time_nsec={}\n", time.subsec_nanos()).as_bytes())
                .await
                .ok();
        }

        let (_, tx_bytes, rx_bytes, ..) = p.tunnel.stats_at(Instant::now());

        writer
            .write_all(format!("rx_bytes={rx_bytes}\n").as_bytes())
            .await
            .ok();
        writer
            .write_all(format!("tx_bytes={tx_bytes}\n").as_bytes())
            .await
            .ok();
    }
    0
}

async fn api_set<T: AsyncBufRead + Unpin>(reader: &mut BufReader<T>, d: &mut Device) -> i32 {
    let mut cmd = String::new();

    while reader.read_line(&mut cmd).await.is_ok() {
        cmd.pop(); // remove newline if any
        if cmd.is_empty() {
            return 0; // Done
        }
        {
            let parsed_cmd: Vec<&str> = cmd.split('=').collect();
            if parsed_cmd.len() != 2 {
                return EPROTO;
            }

            let (key, val) = (parsed_cmd[0], parsed_cmd[1]);

            match key {
                "private_key" => match val.parse::<KeyBytes>() {
                    Ok(key_bytes) => {
                        d.set_key(x25519::StaticSecret::from(key_bytes.0)).await;
                    }
                    Err(_) => return EINVAL,
                },
                "listen_port" => match val.parse::<u16>() {
                    Ok(port) => match d.open_listen_socket(port).await {
                        Ok(()) => {} //
                        Err(_) => return EADDRINUSE,
                    },
                    Err(_) => return EINVAL,
                },
                #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
                "fwmark" => match val.parse::<u32>() {
                    Ok(mark) => match d.set_fwmark(mark).await {
                        Ok(()) => {} //
                        Err(_) => return EADDRINUSE,
                    },
                    Err(_) => return EINVAL,
                },
                "replace_peers" => match val.parse::<bool>() {
                    Ok(true) => d.clear_peers(),
                    Ok(false) => {} //
                    Err(_) => return EINVAL,
                },
                "public_key" => match val.parse::<KeyBytes>() {
                    // Indicates a new peer section
                    Ok(key_bytes) => {
                        return api_set_peer(reader, d, x25519::PublicKey::from(key_bytes.0)).await;
                    }
                    Err(_) => return EINVAL,
                },
                _ => return EINVAL,
            }
        }
        cmd.clear();
    }

    0
}

async fn api_set_peer<'a, T: AsyncBufRead + Unpin>(
    reader: &'a mut BufReader<T>,
    d: &mut Device,
    pub_key: x25519::PublicKey,
) -> i32 {
    let mut cmd = String::new();

    let mut remove = false;
    let mut replace_ips = false;
    let mut endpoint = None;
    let mut keepalive = None;
    let mut public_key = pub_key;
    let mut preshared_key = None;
    let mut allowed_ips: Vec<AllowedIP> = vec![];
    while reader.read_line(&mut cmd).await.is_ok() {
        cmd.pop(); // remove newline if any
        if cmd.is_empty() {
            d.update_peer(
                public_key,
                remove,
                replace_ips,
                endpoint,
                allowed_ips.as_slice(),
                keepalive,
                preshared_key,
            )
            .await;
            allowed_ips.clear(); //clear the vector content after update
            return 0; // Done
        }
        {
            let parsed_cmd: Vec<&str> = cmd.splitn(2, '=').collect();
            if parsed_cmd.len() != 2 {
                return EPROTO;
            }
            let (key, val) = (parsed_cmd[0], parsed_cmd[1]);
            match key {
                "remove" => match val.parse::<bool>() {
                    Ok(true) => remove = true,
                    Ok(false) => remove = false,
                    Err(_) => return EINVAL,
                },
                "preshared_key" => match val.parse::<KeyBytes>() {
                    Ok(key_bytes) => preshared_key = Some(key_bytes.0),
                    Err(_) => return EINVAL,
                },
                "endpoint" => match val.parse::<SocketAddr>() {
                    Ok(addr) => endpoint = Some(addr),
                    Err(_) => return EINVAL,
                },
                "persistent_keepalive_interval" => match val.parse::<u16>() {
                    Ok(interval) => keepalive = Some(interval),
                    Err(_) => return EINVAL,
                },
                "replace_allowed_ips" => match val.parse::<bool>() {
                    Ok(true) => replace_ips = true,
                    Ok(false) => replace_ips = false,
                    Err(_) => return EINVAL,
                },
                "allowed_ip" => match val.parse::<AllowedIP>() {
                    Ok(ip) => allowed_ips.push(ip),
                    Err(_) => return EINVAL,
                },
                "public_key" => {
                    // Indicates a new peer section. Commit changes for current peer, and continue to next peer
                    d.update_peer(
                        public_key,
                        remove,
                        replace_ips,
                        endpoint,
                        allowed_ips.as_slice(),
                        keepalive,
                        preshared_key,
                    )
                    .await;
                    allowed_ips.clear(); //clear the vector content after update
                    match val.parse::<KeyBytes>() {
                        Ok(key_bytes) => public_key = key_bytes.0.into(),
                        Err(_) => return EINVAL,
                    }
                }
                "protocol_version" => match val.parse::<u32>() {
                    Ok(1) => {} // Only version 1 is legal
                    _ => return EINVAL,
                },
                _ => return EINVAL,
            }
        }
        cmd.clear();
    }
    0
}
