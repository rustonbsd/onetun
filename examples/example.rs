use std::{
    collections::HashMap, net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener}, str::FromStr as _, sync::Arc, thread::sleep, time::Duration
};

use bytes::BufMut;
use onetun::{
    config::{self, Config, PortForwardConfig},
    events::Bus,
    start_tunnels,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream, sync::Mutex,
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

    let (tcp, udp) = start_tunnels(onetun_config, bus).await.unwrap();

    let dest_map: Mutex<HashMap<String,u16>> = Mutex::new(HashMap::new());

    for _ in 0..10 {
        let tcp = tcp.clone();
        tokio::spawn(async move {
            let domain = "developtheworld.de".to_string();
            let destination = tokio::net::lookup_host(format!("{domain}:80"))
                .await
                .unwrap()
                .next()
                .unwrap();
            

            let local_port = find_free_tcp_port().unwrap();
            let pf = PortForwardConfig {
                source: SocketAddr::new(IpAddr::from_str("127.0.0.1").unwrap(), local_port),
                destination: destination,
                protocol: config::PortProtocol::Tcp,
                remote: true,
            };

            let _ = tcp
                .send(onetun::virtual_iface::VirtualIpDeviceCommand::AddPortForwardConfig(pf))
                .await
                .unwrap();

            println!("PF: {} {}", pf.destination, local_port);
            sleep(Duration::from_millis(2000));
            let con = TcpStream::connect(SocketAddr::new(
                IpAddr::from_str("127.0.0.1").unwrap(),
                local_port as u16,
            ))
            .await;
            println!("CON: {:?}", con);
        });
    }

    sleep(Duration::from_secs(999999));
    Ok(())
}

pub fn find_free_tcp_port() -> anyhow::Result<u16> {
    // Bind to port 0, which lets the OS choose a free port
    let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let listener = TcpListener::bind(addr)?;

    // Get the port number that was assigned
    let local_addr = listener.local_addr()?;
    Ok(local_addr.port())
}
