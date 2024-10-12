use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    str::FromStr as _,
    sync::Arc,
    thread::sleep,
    time::Duration,
};

use bytes::BufMut;
use onetun::{
    config::{self, Config, PortForwardConfig},
    events::Bus,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let req_text = r#"GET / HTTP/1.1
Host: developtheworld.de
Connection: keep-alive
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en-DE;q=0.9,en;q=0.8

"#.as_bytes();

    let onetun_config = Config {
        port_forwards: vec![],
        remote_port_forwards: vec![],
        private_key: Arc::new(
            onetun::config::X25519SecretKey::from_str(
                "EJHiDdrGDd1pJsr/BXoBN2r0Y7nQn6eYxgbCUfmSWWo=",
            )
            .unwrap(),
        ),
        endpoint_public_key: Arc::new(
            onetun::config::X25519PublicKey::from_str(
                "tzSfoiq9ZbCcE5I0Xz9kCrsWksDn0wgvaz9TiHYTmnU=",
            )
            .unwrap(),
        ),
        preshared_key: None,
        endpoint_addr: SocketAddr::new(IpAddr::from_str("37.19.221.143").unwrap(), 51820),
        endpoint_bind_addr: SocketAddr::new(IpAddr::from_str("0.0.0.0").unwrap(), 0),
        source_peer_ip: IpAddr::from_str("10.67.65.251").unwrap(),
        keepalive_seconds: Some(15),
        max_transmission_unit: 1360,
        log: "".to_string(),
        warnings: vec![],
        pcap_file: None,
    };

    let bus = Bus::default();

    let domain = "developtheworld.de".to_string();
    let local_port = socks5_server::onetun::find_free_tcp_port().unwrap();
    let pfs = socks5_server::onetun::execute_port_fotward_config(
        vec![PortForwardConfig {
            source: SocketAddr::new(IpAddr::from_str("127.0.0.1").unwrap(), local_port),
            destination: tokio::net::lookup_host(format!("{domain}:80"))
                .await
                .unwrap()
                .next()
                .unwrap(),
            protocol: config::PortProtocol::Tcp,
            remote: true,
        }],
        &onetun_config,
        &bus,
    )
    .await;
    let pfs2 = socks5_server::onetun::execute_port_fotward_config(
        vec![PortForwardConfig {
            source: SocketAddr::new(IpAddr::from_str("127.0.0.1").unwrap(), local_port + 1),
            destination: tokio::net::lookup_host(format!("{domain}:80"))
                .await
                .unwrap()
                .next()
                .unwrap(),
            protocol: config::PortProtocol::Tcp,
            remote: true,
        }],
        &onetun_config,
        &bus,
    )
    .await;

    for _ in 0..10 {
        tokio::spawn(async move {
            let domain = "developtheworld.de".to_string();
            println!("DOMAIN: {domain}, {local_port}");
            let mut client = TcpStream::connect(SocketAddr::new(
                std::net::IpAddr::V4(Ipv4Addr::from_str(&"127.0.0.1").unwrap()),
                local_port as u16,
            ))
            .await
            .unwrap();

            //let (mut read, mut write) = client.into_split();

            loop {
                let send = client.write(req_text).await.unwrap();
                println!("SEND:  {:?}", send);

                let mut msg: Vec<u8> = vec![0; 10000];

                let mut msg2 = vec![0; 10240];
                //println!("Starting to read! {:?}",client.readable().await.unwrap());
                //println!("{:?}",client.peek(msg).await.unwrap());
                let resp = client.read(&mut msg2).await.unwrap();
                let t = msg.remaining_mut();
                println!("Remaining: {t}");

                println!("RESP:  {} {}", resp, String::from_utf8_lossy(&msg2));
                sleep(Duration::from_secs(2));
            }
        });
    }

    sleep(Duration::from_secs(999999));
    Ok(())
}
mod socks5_server {
    pub(crate) mod onetun {
        use std::{
            borrow::BorrowMut, net::{SocketAddr, TcpListener}, sync::Arc
        };

        use anyhow::Context;

        use once_cell::sync::Lazy;
        use onetun::{
            self,
            config::{Config, PortForwardConfig, PortProtocol},
            events::Bus,
            tunnel::{self, tcp::TcpPortPool, udp::UdpPortPool},
            virtual_device::VirtualIpDevice,
            virtual_iface::{
                tcp::TcpVirtualInterface, udp::UdpVirtualInterface, VirtualInterfacePoll as _,
            },
            wg::WireGuardTunnel,
        };
        use tokio::sync::OnceCell;

        pub static WG_INTERFACE: Lazy<OnceCell<Arc<WireGuardTunnel>>> =
            Lazy::new(|| OnceCell::new());

        pub async fn start_tunnels(
            config: &Config,
            bus: &Bus,
        ) -> anyhow::Result<Arc<WireGuardTunnel>> {
            let wg = WG_INTERFACE
                .get_or_init(|| async {
                    let wg = WireGuardTunnel::new(&config, bus.clone())
                        .await
                        .with_context(|| "Failed to initialize WireGuard tunnel")
                        .unwrap();
                    let wg: Arc<WireGuardTunnel> = Arc::new(wg);

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
                    wg
                })
                .await;

            Ok(wg.clone())
        }

        pub async fn execute_port_fotward_config(
            pfs: Vec<PortForwardConfig>,
            config: &Config,
            bus: &Bus,
        ) -> anyhow::Result<(
            Arc<TcpVirtualInterface>,
            Option<UdpVirtualInterface>,
            TcpPortPool,
            UdpPortPool,
        )> {
            let wg = start_tunnels(config, bus).await.unwrap();

            // ONLY ONCE keep iface and add add_pf fn to virtual iface
            // Initialize the port pool for each protocol
            let tcp_port_pool = TcpPortPool::new();
            let udp_port_pool = UdpPortPool::new();
            let mut tcp_iface: Arc<TcpVirtualInterface>;
            let mut udp_iface: Option<UdpVirtualInterface> = None;

            if pfs.iter().any(|pf| pf.protocol == PortProtocol::Tcp) {
                // TCP device
                let bus = bus.clone();
                let device = VirtualIpDevice::new(
                    PortProtocol::Tcp,
                    bus.clone(),
                    config.max_transmission_unit,
                );

                // Start TCP Virtual Interface
                let port_forwards = pfs.clone();
                tcp_iface = Arc::new(TcpVirtualInterface::new(
                    port_forwards,
                    bus,
                    config.source_peer_ip,
                ));
                tokio::spawn({ 
                    let iface = Arc::clone(&tcp_iface);
                    async move {
                        iface.as_ref().clone().poll_loop(device).await 
                    } });
            }

            if pfs.iter().any(|pf| pf.protocol == PortProtocol::Udp) {
                // UDP device
                let bus = bus.clone();
                let device = VirtualIpDevice::new(
                    PortProtocol::Udp,
                    bus.clone(),
                    config.max_transmission_unit,
                );

                // Start UDP Virtual Interface
                let port_forwards = pfs.clone();
                udp_iface = Some(UdpVirtualInterface::new(
                    port_forwards,
                    bus,
                    config.source_peer_ip,
                ));
                tokio::spawn(async move { udp_iface.unwrap().poll_loop(device).await });
            }

            Ok((tcp_iface, udp_iface, tcp_port_pool, udp_port_pool))
        }

        pub fn add_new_target(
            pfs: Vec<PortForwardConfig>,
            config: Config,
            wg: Arc<WireGuardTunnel>,
            tcp_port_pool: TcpPortPool,
            udp_port_pool: UdpPortPool,
            bus: Bus,
        ) {
            {
                let port_forwards = pfs.clone();
                let source_peer_ip = config.source_peer_ip;

                port_forwards
                    .into_iter()
                    .map(|pf| {
                        (
                            pf,
                            wg.clone(),
                            tcp_port_pool.clone(),
                            udp_port_pool.clone(),
                            bus.clone(),
                        )
                    })
                    .for_each(move |(pf, wg, tcp_port_pool, udp_port_pool, bus)| {
                        // Update virtual interface

                        tokio::spawn(async move {
                            tunnel::port_forward(
                                pf,
                                source_peer_ip,
                                tcp_port_pool,
                                udp_port_pool,
                                wg,
                                bus,
                            )
                            .await
                            .unwrap_or_else(|e| ())
                        });
                    });
            }
        }

        pub fn find_free_tcp_port() -> anyhow::Result<u16> {
            // Bind to port 0, which lets the OS choose a free port
            let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
            let listener = TcpListener::bind(addr)?;

            // Get the port number that was assigned
            let local_addr = listener.local_addr()?;
            Ok(local_addr.port())
        }
    }
}
