#[macro_use]
extern crate log;

use std::sync::Arc;

use anyhow::Context;
use tokio::sync::Mutex;

use crate::config::{Config, PortProtocol};
use crate::events::Bus;
use crate::tunnel::tcp::TcpPortPool;
use crate::tunnel::udp::UdpPortPool;
use crate::virtual_device::VirtualIpDevice;
use crate::virtual_iface::tcp::TcpVirtualInterface;
use crate::virtual_iface::udp::UdpVirtualInterface;
use crate::virtual_iface::VirtualInterfacePoll;
use crate::wg::WireGuardTunnel;


use tokio::sync::mpsc;
use tokio::sync::mpsc::Sender;

pub mod config;
pub mod events;
#[cfg(feature = "pcap")]
pub mod pcap;
pub mod tunnel;
pub mod virtual_device;
pub mod virtual_iface;
pub mod wg;


pub struct OneTunHandler {
    config: Arc<Config>,
    bus: Arc<Bus>,
    tcp_port_pool: Arc<TcpPortPool>,
    udp_port_pool: Arc<UdpPortPool>,
    wg: Arc<WireGuardTunnel>,
    tcp_virtual_ip_device: Arc<Mutex<VirtualIpDevice>>,
    udp_virtual_ip_device: Arc<VirtualIpDevice>,
    tcp_interface: Arc<Mutex<TcpVirtualInterface>>,
    udp_interface: Arc<UdpVirtualInterface>,
}

/*
#[cfg(feature="dynamic")]
pub async fn start_tunnels(config: Config, bus: Bus) -> anyhow::Result<OneTunHandler> {
    // Initialize the port pool for each protocol
    let tcp_port_pool = TcpPortPool::new();
    let udp_port_pool = UdpPortPool::new();

    #[cfg(feature = "pcap")]
    if let Some(pcap_file) = config.pcap_file.clone() {
        // Start packet capture
        let bus = bus.clone();
        tokio::spawn(async move { pcap::capture(pcap_file, bus).await });
    }

    let wg = WireGuardTunnel::new(&config, bus.clone())
        .await
        .with_context(|| "Failed to initialize WireGuard tunnel")?;
    let wg = Arc::new(wg);

    {
        // Start routine task for WireGuard
        let wg = wg.clone();
        tokio::spawn(async move { wg.routine_task().await });
    }

    {
        // Start consumption task for WireGuard
        let wg = wg.clone();
        tokio::spawn(Box::pin(async move { wg.consume_task().await }));
    }

    {
        // Start production task for WireGuard
        let wg = wg.clone();
        tokio::spawn(async move { wg.produce_task().await });
    }


    // TCP device
    let tcp_device =
        Arc::new(Mutex::new(VirtualIpDevice::new(PortProtocol::Tcp, bus.clone(), config.max_transmission_unit)));

    // Start TCP Virtual Interface
    let tcp_iface = Arc::new(Mutex::new(TcpVirtualInterface::new(vec![], bus, config.source_peer_ip)));
    tokio::spawn(
        async move {  
        
        let tcp_iface = tcp_iface.clone();
        let tcp_device = tcp_device.clone();
        (*tcp_iface.lock().await).poll_loop(tcp_device.lock().await.deref().clone()); 
    
    });

    
    // UDP device;
    let udp_device =
        Arc::new(VirtualIpDevice::new(PortProtocol::Udp, bus.clone(), config.max_transmission_unit));

    // Start UDP Virtual Interface
    let udp_iface = Arc::new(UdpVirtualInterface::new(vec![], bus, config.source_peer_ip));
    tokio::spawn(async move {  
        
        let udp_iface = Arc::clone(&udp_iface);
        let udp_device = Arc::clone(&udp_device);
        udp_iface.poll_loop(*udp_device); 
    
    });
    
    Ok(OneTunHandler{
        config: Arc::new(config),
        bus: Arc::new(bus),
        tcp_port_pool: Arc::new(tcp_port_pool),
        udp_port_pool: Arc::new(udp_port_pool),
        wg: wg,
        tcp_virtual_ip_device: tcp_device,
        udp_virtual_ip_device: udp_device,
        tcp_interface: tcp_iface,
        udp_interface: udp_iface,
    })

}*/

/// Starts the onetun tunnels in separate tokio tasks.
///
/// Note: This future completes immediately.
#[cfg(not(feature="dynamic"))]
pub async fn start_tunnels(config: Config, bus: Bus) -> anyhow::Result<(Sender<virtual_iface::VirtualIpDeviceCommand>,Sender<virtual_iface::VirtualIpDeviceCommand>)> {
    // Initialize the port pool for each protocol
    let tcp_port_pool = TcpPortPool::new();
    let udp_port_pool = UdpPortPool::new();

    #[cfg(feature = "pcap")]
    if let Some(pcap_file) = config.pcap_file.clone() {
        // Start packet capture
        let bus = bus.clone();
        tokio::spawn(async move { pcap::capture(pcap_file, bus).await });
    }

    let wg = WireGuardTunnel::new(&config, bus.clone())
        .await
        .with_context(|| "Failed to initialize WireGuard tunnel")?;
    let wg = Arc::new(wg);

    {
        // Start routine task for WireGuard
        let wg = wg.clone();
        tokio::spawn(async move { wg.routine_task().await });
    }

    {
        // Start consumption task for WireGuard
        let wg = wg.clone();
        tokio::spawn(Box::pin(async move { wg.consume_task().await }));
    }

    {
        // Start production task for WireGuard
        let wg = wg.clone();
        tokio::spawn(async move { wg.produce_task().await });
    }

    let (tcp_sender,tcp_receiver) = mpsc::channel(1);
    
    // TCP device
    let bus = bus.clone();
    let tcp_device =
        VirtualIpDevice::new(PortProtocol::Tcp, bus.clone(), config.max_transmission_unit);

    // Start TCP Virtual Interface
    let port_forwards = vec![];
    let tcp_iface = TcpVirtualInterface::new(port_forwards, bus, config.source_peer_ip);
    tokio::spawn({ let wg = wg.clone(); async move { tcp_iface.poll_loop(tcp_device,tcp_receiver,wg.clone()).await }});
    

    let (udp_sender,udp_receiver) = mpsc::channel(100);
    
    /*/
    // UDP device
    let bus = bus.clone();
    let device =
        VirtualIpDevice::new(PortProtocol::Udp, bus.clone(), config.max_transmission_unit);

    // Start UDP Virtual Interface
    let port_forwards = config.port_forwards.clone();
    let iface = UdpVirtualInterface::new(port_forwards, bus, config.source_peer_ip);
    tokio::spawn({ let wg = wg.clone(); async move { iface.poll_loop(device,udp_receiver,wg.clone()).await }});
    */
    Ok((tcp_sender,udp_sender))
}
