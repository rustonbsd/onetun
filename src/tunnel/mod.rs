use std::net::{IpAddr};
use std::sync::Arc;

use tokio::net::TcpStream;

use crate::config::{PortForwardConfig, PortProtocol};
use crate::events::Bus;
use crate::tunnel::tcp::TcpPortPool;
use crate::tunnel::udp::UdpPortPool;
use crate::wg::WireGuardTunnel;

pub mod tcp;
pub mod udp;

pub async fn port_forward(
    port_forward: PortForwardConfig,
    source_peer_ip: IpAddr,
    tcp_port_pool: TcpPortPool,
    udp_port_pool: UdpPortPool,
    wg: Arc<WireGuardTunnel>,
    bus: Bus,
) -> anyhow::Result<()> {
    info!(
        "Tunneling {} [{}]->[{}] (via [{}] as peer {})",
        port_forward.protocol,
        port_forward.source,
        port_forward.destination,
        &wg.endpoint,
        source_peer_ip
    );

    match port_forward.protocol {
        PortProtocol::Tcp => tcp::tcp_proxy_server(port_forward, tcp_port_pool, bus).await,
        PortProtocol::Udp => udp::udp_proxy_server(port_forward, udp_port_pool, bus).await,
    }
}

pub async fn handle_tcp_port_forward(stream: TcpStream, port_forward: &PortForwardConfig, source_peer_ip: &IpAddr, tcp_port_pool: &mut TcpPortPool, wg: Arc<WireGuardTunnel>, bus: &Bus) -> anyhow::Result<()> {
    let vport = tcp_port_pool.next().await.unwrap();

    tcp::handle_tcp_proxy_connection(stream, vport, port_forward.clone(), bus.clone()).await
}