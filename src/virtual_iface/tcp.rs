use crate::config::{PortForwardConfig, PortProtocol};
use crate::events::Event;
use crate::tunnel::tcp::TcpPortPool;
use crate::tunnel::udp::UdpPortPool;
use crate::virtual_device::VirtualIpDevice;
use crate::virtual_iface::{VirtualInterfacePoll, VirtualPort};
use crate::wg::WireGuardTunnel;
use crate::{tunnel, Bus};
use anyhow::{bail, Context};
use async_trait::async_trait;
use bytes::Bytes;
use smoltcp::socket;
use smoltcp::{
    iface::{Config, Interface, SocketHandle, SocketSet},
    socket::tcp,
    time::Instant,
    wire::{HardwareAddress, IpAddress, IpCidr, IpVersion},
};
use std::sync::Arc;
use std::{
    collections::{HashMap, HashSet, VecDeque},
    net::IpAddr,
    time::Duration,
};
use tokio::sync::{mpsc, Mutex};

use super::VirtualIpDeviceCommand;

const MAX_PACKET: usize = 65536;

/// A virtual interface for proxying Layer 7 data to Layer 3 packets, and vice-versa.
pub struct TcpVirtualInterface {
    source_peer_ip: IpAddr,
    port_forwards: Vec<PortForwardConfig>,
    bus: Bus,
    sockets: Arc<Mutex<SocketSet<'static>>>,
    iface: Option<Interface>,
}

impl TcpVirtualInterface {
    /// Initialize the parameters for a new virtual interface.
    /// Use the `poll_loop()` future to start the virtual interface poll loop.
    pub fn new(port_forwards: Vec<PortForwardConfig>, bus: Bus, source_peer_ip: IpAddr) -> Self {
        Self {
            port_forwards: port_forwards
                .into_iter()
                .filter(|f| matches!(f.protocol, PortProtocol::Tcp))
                .collect(),
            source_peer_ip,
            bus,
            sockets: Arc::new(Mutex::new(SocketSet::new([]))),
            iface: None,
        }
    }

    fn new_server_socket(port_forward: PortForwardConfig) -> anyhow::Result<tcp::Socket<'static>> {
        static mut TCP_SERVER_RX_DATA: [u8; 0] = [];
        static mut TCP_SERVER_TX_DATA: [u8; 0] = [];

        let tcp_rx_buffer = tcp::SocketBuffer::new(unsafe { &mut TCP_SERVER_RX_DATA[..] });
        let tcp_tx_buffer = tcp::SocketBuffer::new(unsafe { &mut TCP_SERVER_TX_DATA[..] });
        let mut socket = tcp::Socket::new(tcp_rx_buffer, tcp_tx_buffer);

        socket
            .listen((
                IpAddress::from(port_forward.destination.ip()),
                port_forward.destination.port(),
            ))
            .with_context(|| "Virtual server socket failed to listen")?;

        Ok(socket)
    }

    fn new_client_socket() -> anyhow::Result<tcp::Socket<'static>> {
        let rx_data = vec![0u8; MAX_PACKET];
        let tx_data = vec![0u8; MAX_PACKET];
        let tcp_rx_buffer = tcp::SocketBuffer::new(rx_data);
        let tcp_tx_buffer = tcp::SocketBuffer::new(tx_data);
        let socket = tcp::Socket::new(tcp_rx_buffer, tcp_tx_buffer);
        Ok(socket)
    }

    fn addresses(&self) -> Vec<IpCidr> {
        let mut addresses = HashSet::new();
        addresses.insert(IpAddress::from(self.source_peer_ip));
        for config in self.port_forwards.iter() {
            addresses.insert(IpAddress::from(config.destination.ip()));
        }
        addresses
            .into_iter()
            .map(|addr| IpCidr::new(addr, addr_length(&addr)))
            .collect()
    }

    fn address(&self, pf: &PortForwardConfig) -> Vec<IpCidr> {
        let mut addresses = HashSet::new();
        addresses.insert(IpAddress::from(self.source_peer_ip));
        addresses.insert(IpAddress::from(pf.destination.ip()));
        addresses
            .into_iter()
            .map(|addr| IpCidr::new(addr, addr_length(&addr)))
            .collect()
    }

    async fn add_new_target(&mut self, pf: &PortForwardConfig) -> anyhow::Result<()> {
        match TcpVirtualInterface::new_server_socket(*pf) {
            Ok(server_socket) => {
                // Create CIDR block for source peer IP + each port forward IP
                let addresses = self.address(pf);
                {
                    let mut sockets = self.sockets.lock().await;
                    sockets.add(server_socket);
                }
                self.iface.as_mut().unwrap().update_ip_addrs(|ip_addrs| {
                    addresses.into_iter().for_each(|addr| {
                        ip_addrs.push(addr).unwrap();
                    });
                });

                Ok(())
            }
            Err(_) => {
                println!("failed to create server socker");
                bail!("failed to create server socker");
            }
        }
    }
}

#[async_trait]
impl VirtualInterfacePoll for TcpVirtualInterface {
    async fn poll_loop(
        mut self,
        mut device: VirtualIpDevice,
        mut receiver: mpsc::Receiver<VirtualIpDeviceCommand>,
        wg: Arc<WireGuardTunnel>,
    ) -> anyhow::Result<()> {
        // Create CIDR block for source peer IP + each port forward IP
        let addresses = self.addresses();
        let config = Config::new(HardwareAddress::Ip);

        // Create virtual interface (contains smoltcp state machine)
        let mut iface = Interface::new(config, &mut device, Instant::now());
        iface.update_ip_addrs(|ip_addrs| {
            addresses.into_iter().for_each(|addr| {
                ip_addrs.push(addr).unwrap();
            });
        });

        // Create virtual server for each port forward
        for port_forward in self.port_forwards.iter() {
            let server_socket = TcpVirtualInterface::new_server_socket(*port_forward)?;
            {
                let mut sockets = self.sockets.lock().await;
                sockets.add(server_socket);
            }
        }

        // The next time to poll the interface. Can be None for instant poll.
        let mut next_poll: Option<tokio::time::Instant> = None;

        // Bus endpoint to read events
        let mut endpoint = self.bus.new_endpoint();

        // Maps virtual port to its client socket handle
        let mut port_client_handle_map: HashMap<VirtualPort, SocketHandle> = HashMap::new();

        let mut dest_addr_local_port: Mutex<HashMap<String, u16>> = Mutex::new(HashMap::new());

        // Data packets to send from a virtual client
        let mut send_queue: HashMap<VirtualPort, VecDeque<Bytes>> = HashMap::new();

        let mut tcp_port_pool = TcpPortPool::new();
        let mut udp_port_pool = UdpPortPool::new();
        /*
            port_forward: PortForwardConfig,
            source_peer_ip: IpAddr,
            tcp_port_pool: TcpPortPool,
            udp_port_pool: UdpPortPool,
            wg: Arc<WireGuardTunnel>,
            bus: Bus,
        */

        tokio::task::spawn({
            let sockets = Arc::clone(&self.sockets);
            async move {

            loop {
                println!("Update");
                tokio::select! {
                    cmd = receiver.recv() => match cmd {
                        Some(VirtualIpDeviceCommand::AddPortForwardConfig(pf)) => {

                            println!("Loop Trigger");

                            match dest_addr_local_port.lock().await.contains_key(&pf.destination.to_string()) {
                                true => {
                                    println!("Port already forwarded!");
                                    continue;
                                },
                                false => println!("Port forward"),

                            };

                            // Virtual Setup
                            match TcpVirtualInterface::new_server_socket(pf) {
                                Ok(server_socket) => {
                                    {
                                        match sockets.try_lock() {
                                            Ok(mut sockets) => {
                                                sockets.add(server_socket);
                                            },
                                            Err(_) => {println!("LockFailed");},
                                        };
                                    }
                                    self.port_forwards.push(pf);

                                    // Add port forward config
                                    let source_peer_ip = self.source_peer_ip.clone();
                                    let tcp_port_pool = tcp_port_pool.clone();
                                    let udp_port_pool = udp_port_pool.clone();
                                    let bus = self.bus.clone();
                                    let wg = Arc::clone(&wg);

                                    tokio::spawn(async move {
                                        let ret = tunnel::port_forward(pf, source_peer_ip, tcp_port_pool, udp_port_pool, wg, bus)
                                            .await
                                            .unwrap_or_else(|e| error!("Port-forward failed for {} : {}", pf, e));
                                        ret
                                    });

                                    println!("WORKING: {}",pf.destination.to_string());


                                    //dest_addr_local_port.lock().await.insert(pf.destination.to_string(),pf.source.port());
                                },
                                Err(_) => {},
                            };
                        },
                        _ => {},
                    },
                }
            }
        }
        });

        loop {
            tokio::select! {
                _ = match (next_poll, port_client_handle_map.len()) {
                    (None, 0) => tokio::time::sleep(Duration::MAX),
                    (None, _) => tokio::time::sleep(Duration::ZERO),
                    (Some(until), _) => tokio::time::sleep_until(until),
                } => {
                    let loop_start = smoltcp::time::Instant::now();

                    // Find closed sockets
                    port_client_handle_map.retain(|virtual_port, client_handle| {
                        {
                            match self.sockets.try_lock() {
                                Ok(mut sockets) => {
                                    let client_socket = sockets.get_mut::<tcp::Socket>(*client_handle);

                                    if client_socket.state() == tcp::State::Closed {
                                        endpoint.send(Event::ClientConnectionDropped(*virtual_port));
                                        send_queue.remove(virtual_port);
                                        sockets.remove(*client_handle);
                                        false
                                    } else {
                                        // Not closed, retain
                                        true
                                    }
                                },
                                Err(_) => { 
                                    println!("LockFailed!");
                                    true},
                            }
                        }
                    });

                    {
                        match self.sockets.try_lock() {
                            Ok(mut sockets) => {
                                if iface.poll(loop_start, &mut device, &mut sockets) {
                                    log::trace!("TCP virtual interface polled some packets to be processed");
                                }
                            },
                            Err(_) => {println!("LockFailed");},
                        };
                        
                    }

                    for (virtual_port, client_handle) in port_client_handle_map.iter() {
                        {
                            match self.sockets.try_lock() {
                                Ok(mut sockets) => {
                                    let client_socket = sockets.get_mut::<tcp::Socket>(*client_handle);
                                    if client_socket.can_send() {
                                        if let Some(send_queue) = send_queue.get_mut(virtual_port) {
                                            let to_transfer = send_queue.pop_front();
                                            if let Some(to_transfer_slice) = to_transfer.as_deref() {
                                                let total = to_transfer_slice.len();
                                                match client_socket.send_slice(to_transfer_slice) {
                                                    Ok(sent) => {
                                                        if sent < total {
                                                            // Sometimes only a subset is sent, so the rest needs to be sent on the next poll
                                                            let tx_extra = Vec::from(&to_transfer_slice[sent..total]);
                                                            send_queue.push_front(tx_extra.into());
                                                        }
                                                    }
                                                    Err(e) => {
                                                        error!(
                                                            "Failed to send slice via virtual client socket: {:?}", e
                                                        );
                                                    }
                                                }
                                            } else if client_socket.state() == tcp::State::CloseWait {
                                                client_socket.close();
                                            }
                                        }
                                    }
                                    if client_socket.can_recv() {
                                        match client_socket.recv(|buffer| (buffer.len(), Bytes::from(buffer.to_vec()))) {
                                            Ok(data) => {
                                                debug!("[{}] Received {} bytes from virtual server", virtual_port, data.len());
                                                if !data.is_empty() {
                                                    endpoint.send(Event::RemoteData(*virtual_port, data));
                                                }
                                            }
                                            Err(e) => {
                                                error!(
                                                    "Failed to read from virtual client socket: {:?}", e
                                                );
                                            }
                                        }
                                    }
                                },
                                Err(_) => {},
                            };
                            
                        }
                    }

                    // The virtual interface determines the next time to poll (this is to reduce unnecessary polls)
                    {
                        match self.sockets.try_lock() {
                            Ok(sockets) => {
                                next_poll = match iface.poll_delay(loop_start, &sockets) {
                                    Some(smoltcp::time::Duration::ZERO) => None,
                                    Some(delay) => {
                                        trace!("TCP Virtual interface delayed next poll by {}", delay);
                                        Some(tokio::time::Instant::now() + Duration::from_millis(delay.total_millis()))
                                    },
                                    None => None,
                                };
                            },
                            Err(_) => {},
                        };
                        
                    }
                }
                event = endpoint.recv() => {
                    match event {
                        Event::ClientConnectionInitiated(port_forward, virtual_port) => {
                            {
                                match self.sockets.try_lock() {
                                    Ok(mut sockets) => {
                                        let client_socket = TcpVirtualInterface::new_client_socket()?;
                                        let client_handle = sockets.add(client_socket);
            
                                        // Add handle to map
                                        port_client_handle_map.insert(virtual_port, client_handle);
                                        send_queue.insert(virtual_port, VecDeque::new());
            
                                        let client_socket = sockets.get_mut::<tcp::Socket>(client_handle);
                                        let context = iface.context();
            
                                        client_socket
                                            .connect(
                                                context,
                                                (
                                                    IpAddress::from(port_forward.destination.ip()),
                                                    port_forward.destination.port(),
                                                ),
                                                (IpAddress::from(self.source_peer_ip), virtual_port.num()),
                                            )
                                            .with_context(|| "Virtual server socket failed to listen")?;
            
                                        next_poll = None;
                                    },
                                    Err(_) => {}
                                }
                            }
                            
                        }
                        Event::ClientConnectionDropped(virtual_port) => {
                            if let Some(client_handle) = port_client_handle_map.get(&virtual_port) {
                                {
                                    match self.sockets.try_lock() {
                                        Ok(mut sockets) => {
                                            let client_socket = sockets.get_mut::<tcp::Socket>(*client_handle);
                                            client_socket.close();
                                            next_poll = None;
                                        },
                                        Err(_) => {},
                                    };
                                }
                            }
                        }
                        Event::LocalData(_, virtual_port, data) if send_queue.contains_key(&virtual_port) => {
                            if let Some(send_queue) = send_queue.get_mut(&virtual_port) {
                                send_queue.push_back(data);
                                next_poll = None;
                            }
                        }
                        Event::VirtualDeviceFed(PortProtocol::Tcp) => {
                            next_poll = None;
                        }
                        _ => {}
                    }
                }
            }
        }
    }
}

const fn addr_length(addr: &IpAddress) -> u8 {
    match addr.version() {
        IpVersion::Ipv4 => 32,
        IpVersion::Ipv6 => 128,
    }
}
