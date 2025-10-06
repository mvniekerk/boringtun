// Copyright (c) 2019 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

pub mod allowed_ips;
pub mod api;
pub mod drop_privileges;
#[cfg(test)]
mod integration_tests;
pub mod peer;

#[cfg(any(target_os = "macos", target_os = "ios", target_os = "tvos"))]
#[path = "kqueue.rs"]
pub mod poll;

#[cfg(target_os = "linux")]
#[path = "epoll.rs"]
pub mod poll;

#[cfg(any(target_os = "macos", target_os = "ios", target_os = "tvos"))]
#[path = "tun_darwin.rs"]
pub mod tun;

#[cfg(target_os = "linux")]
#[path = "tun_linux.rs"]
pub mod tun;

use std::collections::HashMap;
use std::fmt::{Debug, Formatter};
use std::io::{self, Write as _};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
#[cfg(unix)]
use std::os::unix::io::{AsRawFd, FromRawFd};
use std::sync::atomic::AtomicUsize;
use std::sync::Arc;
use std::time::Instant;

use crate::noise::handshake::parse_handshake_anon;
use crate::noise::rate_limiter::RateLimiter;
use crate::noise::{Index, Packet, Tunn, TunnResult};
use crate::x25519;
use allowed_ips::AllowedIps;
use peer::{AllowedIP, Peer};
use rand::{rngs::OsRng, RngCore};
use socket2::{Domain, Protocol, Type};
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, RwLock};
use tokio::task::JoinHandle;
use tracing::{debug, error};
use tun::TunSocket;

const HANDSHAKE_RATE_LIMIT: u64 = 100; // The number of handshakes per second we can tolerate before using cookies

const MAX_UDP_SIZE: usize = (1 << 16) - 1;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("i/o error: {0}")]
    IoError(#[from] io::Error),
    #[error("{0}")]
    Socket(io::Error),
    #[error("{0}")]
    Bind(String),
    #[error("{0}")]
    FCntl(io::Error),
    #[error("{0}")]
    EventQueue(io::Error),
    #[error("{0}")]
    IOCtl(io::Error),
    #[error("{0}")]
    Connect(String),
    #[error("{0}")]
    SetSockOpt(String),
    #[error("Invalid tunnel name")]
    InvalidTunnelName,
    #[cfg(any(target_os = "macos", target_os = "ios", target_os = "tvos"))]
    #[error("{0}")]
    GetSockOpt(io::Error),
    #[error("{0}")]
    GetSockName(String),
    #[cfg(target_os = "linux")]
    #[error("{0}")]
    Timer(io::Error),
    #[error("iface read: {0}")]
    IfaceRead(io::Error),
    #[error("{0}")]
    DropPrivileges(String),
    #[error("API socket error: {0}")]
    ApiSocket(io::Error),
}

pub struct DeviceHandle {
    device: Arc<RwLock<Device>>, // The interface this handle owns
    threads: Vec<JoinHandle<()>>,
    stop_tx: mpsc::Sender<()>,
}

#[derive(Debug, Clone, Copy)]
pub struct DeviceConfig {
    pub n_threads: usize,
    pub use_connected_socket: bool,
    #[cfg(target_os = "linux")]
    pub use_multi_queue: bool,
    #[cfg(target_os = "linux")]
    pub uapi_fd: i32,
    pub listen_port: Option<u16>
}

impl Default for DeviceConfig {
    fn default() -> Self {
        DeviceConfig {
            n_threads: 4,
            use_connected_socket: true,
            #[cfg(target_os = "linux")]
            use_multi_queue: true,
            #[cfg(target_os = "linux")]
            uapi_fd: -1,
            listen_port: None
        }
    }
}

pub struct Device {
    key_pair: Option<(x25519::StaticSecret, x25519::PublicKey)>,

    listen_port: u16,
    fwmark: Option<u32>,

    pub iface: Arc<TunSocket>,
    udp4: Option<Arc<UdpSocket>>,
    udp6: Option<Arc<UdpSocket>>,

    peers: HashMap<x25519::PublicKey, Arc<RwLock<Peer>>>,
    peers_by_ip: AllowedIps<Arc<RwLock<Peer>>>,
    peers_by_idx: HashMap<u32, Arc<RwLock<Peer>>>,
    next_index: IndexLfsr,

    pub config: DeviceConfig,

    cleanup_paths: Vec<String>,

    pub mtu: AtomicUsize,

    rate_limiter: Option<Arc<RateLimiter>>,

    #[cfg(target_os = "linux")]
    pub uapi_fd: i32,
}

impl Debug for Device {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let mut dbg = f.debug_struct("Device");

        dbg.field("key_pair", &self.key_pair.as_ref().map(|(_, pk)| pk))
            .field("listen_port", &self.listen_port)
            .field("fwmark", &self.fwmark)
            .field("iface", &self.iface)
            .field("udp4", &self.udp4)
            .field("udp6", &self.udp6)
            .field("peers", &self.peers)
            .field("peers_by_ip", &self.peers_by_ip)
            .field("peers_by_idx", &self.peers_by_idx)
            .field("next_index", &self.next_index)
            .field("config", &self.config)
            .field("cleanup_paths", &self.cleanup_paths)
            .field("mtu", &self.mtu)
            .field("rate_limiter", &self.rate_limiter);

        #[cfg(target_os = "linux")]
        {
            dbg.field("uapi_fd", &self.uapi_fd);
        }
        dbg.finish()
    }
}

impl DeviceHandle {
    pub async fn new(name: &str, config: DeviceConfig) -> Result<DeviceHandle, Error> {
        let (stop_tx, stop_rx) = mpsc::channel(1);
        let (iface_tx, iface_rx) = mpsc::channel(1024);
        let interface_lock = Device::new(name, config).await?;
        let mut threads = vec![];

        threads.push({
            let dev = Arc::clone(&interface_lock);
            tokio::spawn(Self::iface_handler(dev, iface_tx))
        });

        threads.push({
            let dev = Arc::clone(&interface_lock);
            tokio::spawn(Self::udp_handler(dev, stop_rx, iface_rx))
        });

        Ok(DeviceHandle {
            device: interface_lock,
            threads,
            stop_tx,
        })
    }

    pub fn device(&self) -> Arc<RwLock<Device>> {
        Arc::clone(&self.device)
    }

    pub async fn wait(&mut self) {
        for thread in self.threads.drain(..) {
            if let Err(e) = thread.await {
                error!(?e, "Join error on .wait");
            }
        }
    }

    pub(crate) fn clean(cleanup_paths: &Vec<String>) {
        for path in cleanup_paths {
            // attempt to remove any file we created in the work dir
            let _ = std::fs::remove_file(path);
        }
    }

    async fn udp_handler(
        device: Arc<RwLock<Device>>,
        mut stop_rx: mpsc::Receiver<()>,
        mut iface_rx: mpsc::Receiver<Vec<u8>>,
    ) {
        let mut src_buf4 = [0u8; MAX_UDP_SIZE];
        let mut src_buf6 = [0u8; MAX_UDP_SIZE];
        let mut dst_buf = [0u8; MAX_UDP_SIZE];

        let (udp4, udp6) = {
            let d = device.read().await;
            (d.udp4.clone(), d.udp6.clone())
        };

        let (udp4, udp6) = match (udp4, udp6) {
            (Some(udp4), Some(udp6)) => (udp4, udp6),
            (Some(_), None) => {
                error!("Udp6 not defined");
                return;
            }
            (None, Some(_)) => {
                error!("Udp4 not defined");
                return;
            }
            (None, None) => {
                error!("Both udp4 and udp6 not defined");
                return;
            }
        };

        loop {
            debug!("Loop on iface/udp rx");
            tokio::select! {
                _ = stop_rx.recv() => return,
                Some(packet) = iface_rx.recv() => {
                    Self::handle_iface_packet(device.clone(), &packet, &mut dst_buf).await;
                }
                Ok((size, addr)) = udp4.recv_from(&mut src_buf4) => {
                    Self::handle_udp_packet(device.clone(), &udp4, &src_buf4[..size], &mut dst_buf, addr).await;
                }
                Ok((size, addr)) = udp6.recv_from(&mut src_buf6) => {
                    Self::handle_udp_packet(device.clone(), &udp6, &src_buf6[..size], &mut dst_buf, addr).await;
                }
            }
        }
    }

    async fn iface_handler(device: Arc<RwLock<Device>>, iface_tx: mpsc::Sender<Vec<u8>>) {
        let mut buf = [0u8; MAX_UDP_SIZE];
        let iface = device.read().await.iface.clone();
        loop {
            if let Ok(r) = iface.read(&mut buf) {
                debug!("Read from iface");
                if let Err(e) = iface_tx.send(r.to_vec()).await {
                    error!(?e, "Error sending iface packet")
                }
            }
        }
    }

    async fn handle_iface_packet(device: Arc<RwLock<Device>>, src: &[u8], dst_buf: &mut [u8]) {
        debug!("Handle iface packet");
        let d = device.read().await;
        if d.udp4.is_none() || d.udp6.is_none() {
            error!(?d, "No UDP4 or UDP6 packet, bailing on handle iface packet");
            return;
        }

        let dst_addr = match Tunn::dst_address(src) {
            Some(addr) => addr,
            None => return,
        };

        let peer = match d.peers_by_ip.find(dst_addr) {
            Some(peer) => peer,
            None => return,
        };

        let mut p = peer.write().await;

        match p.tunnel.encapsulate_at(src, dst_buf, Instant::now()) {
            TunnResult::Done => {}
            TunnResult::Err(error) => {
                tracing::error!(?error, "Encapsulate error")
            }
            TunnResult::WriteToNetwork(packet) => {
                let mut endpoint = p.endpoint_mut().await;
                if let Some(conn) = endpoint.conn.as_mut() {
                    // Prefer to send using the connected socket
                    let _ = conn.write(packet);
                } else if let Some(addr @ SocketAddr::V4(_)) = endpoint.addr {
                    let _ = d.udp4.as_ref().unwrap().send_to(packet, addr).await;
                } else if let Some(addr @ SocketAddr::V6(_)) = endpoint.addr {
                    let _ = d.udp6.as_ref().unwrap().send_to(packet, addr).await;
                } else {
                    tracing::error!("No endpoint");
                }
            }
            _ => panic!("Unexpected result from encapsulate"),
        };
    }

    async fn handle_udp_packet(
        device: Arc<RwLock<Device>>,
        udp: &UdpSocket,
        packet: &[u8],
        dst_buf: &mut [u8],
        addr: SocketAddr,
    ) {
        debug!("Handle UDP packet");
        let d = device.read().await;
        if d.rate_limiter.is_none() {
            error!("No rate limiter, bailing on handle_udp_packet");
            return;
        }
        let (private_key, public_key) = d.key_pair.as_ref().expect("Key not set");
        let rate_limiter = d.rate_limiter.as_ref().unwrap();

        let parsed_packet =
            match rate_limiter.verify_packet_at(Some(addr.ip()), packet, dst_buf, Instant::now()) {
                Ok(packet) => packet,
                Err(TunnResult::WriteToNetwork(cookie)) => {
                    let _ = udp.send_to(cookie, &addr).await;
                    return;
                }
                Err(_) => return,
            };

        let peer = match &parsed_packet {
            Packet::HandshakeInit(p) => parse_handshake_anon(private_key, public_key, p)
                .ok()
                .and_then(|hh| d.peers.get(&x25519::PublicKey::from(hh.peer_static_public))),
            Packet::HandshakeResponse(p) => d.peers_by_idx.get(&(p.receiver_idx >> 8)),
            Packet::PacketCookieReply(p) => d.peers_by_idx.get(&(p.receiver_idx >> 8)),
            Packet::PacketData(p) => d.peers_by_idx.get(&(p.receiver_idx >> 8)),
        };

        let peer = match peer {
            None => return,
            Some(peer) => peer,
        };

        let mut p = peer.write().await;

        let mut flush = false;
        match p
            .tunnel
            .handle_verified_packet(parsed_packet, dst_buf, Instant::now())
        {
            TunnResult::Done => {}
            TunnResult::Err(_) => return,
            TunnResult::WriteToNetwork(packet) => {
                flush = true;
                let _ = udp.send_to(packet, &addr).await;
            }
            TunnResult::WriteToTunnelV4(packet, addr) => {
                if p.is_allowed_ip(addr) {
                    d.iface.write4(packet);
                }
            }
            TunnResult::WriteToTunnelV6(packet, addr) => {
                if p.is_allowed_ip(addr) {
                    d.iface.write6(packet);
                }
            }
        };

        if flush {
            while let TunnResult::WriteToNetwork(packet) =
                p.tunnel.decapsulate_at(None, &[], dst_buf, Instant::now())
            {
                let _ = udp.send_to(packet, &addr).await;
            }
        }

        p.set_endpoint(addr).await;
    }
}

impl Drop for DeviceHandle {
    fn drop(&mut self) {
        let device = self.device.clone();
        let stop_tx = self.stop_tx.clone();
        tokio::spawn(async move {
            if let Err(e) = stop_tx.send(()).await {
                error!(?e, "Error sending stop signal");
            }
            let device = device.read().await;
            Self::clean(&device.cleanup_paths);
        });
    }
}

impl Device {
    fn next_index(&mut self) -> u32 {
        self.next_index.next()
    }

    pub async fn remove_peer(&mut self, pub_key: &x25519::PublicKey) {
        if let Some(peer) = self.peers.remove(pub_key) {
            {
                let p = peer.read().await;
                self.peers_by_idx.remove(&p.index());
            }
            self.peers_by_ip
                .remove(&|p: &Arc<RwLock<Peer>>| Arc::ptr_eq(&peer, p));

            tracing::info!("Peer removed");
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn update_peer(
        &mut self,
        pub_key: x25519::PublicKey,
        remove: bool,
        _replace_ips: bool,
        endpoint: Option<SocketAddr>,
        allowed_ips: &[AllowedIP],
        keepalive: Option<u16>,
        preshared_key: Option<[u8; 32]>,
    ) {
        if remove {
            // Completely remove a peer
            return self.remove_peer(&pub_key).await;
        }

        // Update an existing peer
        if self.peers.contains_key(&pub_key) {
            // We already have a peer, we need to merge the existing config into the newly created one
            panic!("Modifying existing peers is not yet supported. Remove and add again instead.");
        }

        let next_index = self.next_index();
        let device_key_pair = self
            .key_pair
            .as_ref()
            .expect("Private key must be set first");

        let tunn = Tunn::new_at(
            device_key_pair.0.clone(),
            pub_key,
            preshared_key,
            keepalive,
            Index::new_local(next_index),
            None,
            rand::random(),
            Instant::now(),
        );

        let peer = Peer::new(tunn, next_index, endpoint, allowed_ips, preshared_key);

        let peer = Arc::new(RwLock::new(peer));
        self.peers.insert(pub_key, Arc::clone(&peer));
        self.peers_by_idx.insert(next_index, Arc::clone(&peer));

        for AllowedIP { addr, cidr } in allowed_ips {
            self.peers_by_ip
                .insert(*addr, *cidr as _, Arc::clone(&peer));
        }

        tracing::info!("Peer added");
    }

    pub fn peers(&self) -> Vec<x25519::PublicKey> {
        self.peers.keys().cloned().collect()
    }

    pub async fn new(name: &str, config: DeviceConfig) -> Result<Arc<RwLock<Device>>, Error> {
        let iface = Arc::new(TunSocket::new(name)?.set_non_blocking()?);
        let mtu = iface.mtu()?;

        #[cfg(not(target_os = "linux"))]
        let uapi_fd = -1;
        #[cfg(target_os = "linux")]
        let uapi_fd = config.uapi_fd;
        let listen_port = config.listen_port.unwrap_or(0);

        let device_arc = Arc::new(RwLock::new(Device {
            iface,
            config,
            fwmark: Default::default(),
            key_pair: Default::default(),
            listen_port,
            next_index: Default::default(),
            peers: Default::default(),
            peers_by_idx: Default::default(),
            peers_by_ip: AllowedIps::new(),
            udp4: Default::default(),
            udp6: Default::default(),
            cleanup_paths: Default::default(),
            mtu: AtomicUsize::new(mtu),
            rate_limiter: None,
            #[cfg(target_os = "linux")]
            uapi_fd,
        }));
        {
            let mut d = device_arc.write().await;

            if uapi_fd >= 0 {
                d.register_api_fd(uapi_fd, device_arc.clone())?;
            } else {
                d.register_api_handler(device_arc.clone())?;
            }
            d.open_listen_socket(listen_port).await?;

            #[cfg(target_os = "macos")]
            {
                if let Ok(name_file) = std::env::var("WG_TUN_NAME_FILE") {
                    if name == "utun" {
                        std::fs::write(&name_file, d.iface.name().unwrap().as_bytes()).unwrap();
                        d.cleanup_paths.push(name_file);
                    }
                }
            }
        }

        Ok(device_arc)
    }

    async fn open_listen_socket(&mut self, mut port: u16) -> Result<(), Error> {
        let udp_sock4 = socket2::Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
        udp_sock4.set_reuse_address(true)?;
        udp_sock4.bind(&SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, port).into())?;
        udp_sock4.set_nonblocking(true)?;

        if port == 0 {
            port = udp_sock4.local_addr()?.as_socket().unwrap().port();
        }

        let udp_sock6 = socket2::Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP))?;
        udp_sock6.set_reuse_address(true)?;
        udp_sock6.bind(&SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, port, 0, 0).into())?;
        udp_sock6.set_nonblocking(true)?;

        self.udp4 = Some(Arc::new(UdpSocket::from_std(udp_sock4.into())?));
        self.udp6 = Some(Arc::new(UdpSocket::from_std(udp_sock6.into())?));

        self.listen_port = port;

        Ok(())
    }

    pub async fn set_key(&mut self, private_key: x25519::StaticSecret) {
        let public_key = x25519::PublicKey::from(&private_key);
        let key_pair = Some((private_key.clone(), public_key));

        // x25519 (rightly) doesn't let us expose secret keys for comparison.
        // If the public keys are the same, then the private keys are the same.
        if Some(&public_key) == self.key_pair.as_ref().map(|p| &p.1) {
            return;
        }

        let rate_limiter = Arc::new(RateLimiter::new_at(
            &public_key,
            HANDSHAKE_RATE_LIMIT,
            Instant::now(),
        ));

        for peer in self.peers.values_mut() {
            peer.write().await.tunnel.set_static_private_at(
                private_key.clone(),
                public_key,
                Some(Arc::clone(&rate_limiter)),
                Instant::now(),
            )
        }

        self.key_pair = key_pair;
        self.rate_limiter = Some(rate_limiter);
    }

    #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
    async fn set_fwmark(&mut self, mark: u32) -> Result<(), Error> {
        self.fwmark = Some(mark);

        if let Some(ref sock) = self.udp4 {
            let socket = unsafe { socket2::Socket::from_raw_fd(sock.as_raw_fd()) };
            socket.set_mark(mark)?;
            std::mem::forget(socket);
        }

        if let Some(ref sock) = self.udp6 {
            let socket = unsafe { socket2::Socket::from_raw_fd(sock.as_raw_fd()) };
            socket.set_mark(mark)?;
            std::mem::forget(socket);
        }

        for peer in self.peers.values() {
            if let Some(ref sock) = peer.read().await.endpoint().await.conn {
                sock.set_mark(mark)?
            }
        }

        Ok(())
    }

    fn clear_peers(&mut self) {
        self.peers.clear();
        self.peers_by_idx.clear();
        self.peers_by_ip.clear();
    }
}

/// A basic linear-feedback shift register implemented as xorshift, used to
/// distribute peer indexes across the 24-bit address space reserved for peer
/// identification.
/// The purpose is to obscure the total number of peers using the system and to
/// ensure it requires a non-trivial amount of processing power and/or samples
/// to guess other peers' indices. Anything more ambitious than this is wasted
/// with only 24 bits of space.
#[derive(Debug)]
struct IndexLfsr {
    initial: u32,
    lfsr: u32,
    mask: u32,
}

impl IndexLfsr {
    /// Generate a random 24-bit nonzero integer
    fn random_index() -> u32 {
        const LFSR_MAX: u32 = 0xffffff; // 24-bit seed
        loop {
            let i = OsRng.next_u32() & LFSR_MAX;
            if i > 0 {
                // LFSR seed must be non-zero
                return i;
            }
        }
    }

    /// Generate the next value in the pseudorandom sequence
    fn next(&mut self) -> u32 {
        // 24-bit polynomial for randomness. This is arbitrarily chosen to
        // inject bitflips into the value.
        const LFSR_POLY: u32 = 0xd80000; // 24-bit polynomial
        let value = self.lfsr - 1; // lfsr will never have value of 0
        self.lfsr = (self.lfsr >> 1) ^ ((0u32.wrapping_sub(self.lfsr & 1u32)) & LFSR_POLY);
        assert!(self.lfsr != self.initial, "Too many peers created");
        value ^ self.mask
    }
}

impl Default for IndexLfsr {
    fn default() -> Self {
        let seed = Self::random_index();
        IndexLfsr {
            initial: seed,
            lfsr: seed,
            mask: Self::random_index(),
        }
    }
}
