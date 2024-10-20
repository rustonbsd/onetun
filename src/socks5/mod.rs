use crate::{
    config::{Config, PortForwardConfig},
    events::Bus,
    tunnel::tcp::TcpPortPool,
    wg::WireGuardTunnel,
};
use socks5_server::{
    auth::NoAuth,
    connection::state::NeedAuthenticate,
    proto::{Address, Error, Reply},
    Command, IncomingConnection, Server,
};
use std::{
    io::Error as IoError,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    str::FromStr,
    sync::Arc,
};
use tokio::{
    io::{self, AsyncRead, AsyncWrite, AsyncWriteExt, DuplexStream},
    net::{lookup_host, TcpListener, TcpStream},
};

use base64::prelude::*;

pub async fn start_server() -> Result<(), IoError> {
    let listener = TcpListener::bind("127.0.0.1:5000").await?;
    let auth = Arc::new(NoAuth) as Arc<_>;

    let server = Server::new(listener, auth);
    let mut priv_key_buf = [0u8; 32];
    let mut pub_key_buf = [0u8; 32];

    BASE64_STANDARD
        .decode_slice(
            "CK6RJoOM3fmUeVYUFomyQ3UDZtCSbqOMvotj4ItxmXc=",
            &mut priv_key_buf,
        )
        .unwrap();
    BASE64_STANDARD
        .decode_slice(
            "s1c/NsfnqnwQSxao70DY4Co69AFT9e0h88IFuMD5mjs=",
            &mut pub_key_buf,
        )
        .unwrap();

    /*PortForwardConfig {
            source: SocketAddr::new(
                std::net::IpAddr::V4(Ipv4Addr::from_str("0.0.0.0").unwrap()),
                5001,
            ),
            destination: SocketAddr::from_str("217.160.231.236:80").unwrap(),
            protocol: onetun::config::PortProtocol::Tcp,
            remote: true,
        } */

    let config = Config {
        port_forwards: vec![PortForwardConfig {
            source: SocketAddr::new(
                std::net::IpAddr::V4(Ipv4Addr::from_str("0.0.0.0").unwrap()),
                0,
            ),
            destination: SocketAddr::from_str("1.1.1.1:80").unwrap(),
            protocol: crate::config::PortProtocol::Tcp,
            remote: true,
        }],
        remote_port_forwards: vec![],
        private_key: Arc::new(crate::config::StaticSecret::from(priv_key_buf)),
        endpoint_public_key: Arc::new(crate::config::PublicKey::from(pub_key_buf)),
        preshared_key: None,
        endpoint_addr: SocketAddr::new(IpAddr::from_str("185.213.155.74").unwrap(), 51820),
        endpoint_bind_addr: SocketAddr::new(IpAddr::from_str("0.0.0.0").unwrap(), 0),
        source_peer_ip: IpAddr::from_str("10.72.37.77").unwrap(),
        keepalive_seconds: Some(15),
        max_transmission_unit: 1360,
        log: "".to_string(),
        warnings: vec![],
        pcap_file: None,
    };

    let bus = Bus::default();
    let (tcp_port_pool, wg) = crate::start_wg_tcp_only(&config, &bus).await.unwrap();

    while let Ok((conn, _)) = server.accept().await {
        tokio::spawn({
            let bus = bus.clone();
            let tcp_port_pool = tcp_port_pool.clone();
            let wg = Arc::clone(&wg);
            async move {
                match handle(conn, &bus, tcp_port_pool, Arc::clone(&wg)).await {
                    Ok(()) => {}
                    Err(err) => eprintln!("{err}"),
                }
            }
        });
    }

    Ok(())
}

async fn handle(
    conn: IncomingConnection<(), NeedAuthenticate>,
    bus: &Bus,
    mut tcp_port_pool: TcpPortPool,
    wg: Arc<WireGuardTunnel>,
) -> Result<(), Error> {
    let conn = match conn.authenticate().await {
        Ok((conn, _)) => conn,
        Err((err, mut conn)) => {
            let _ = conn.shutdown().await;
            return Err(err);
        }
    };

    match conn.wait().await {
        Ok(Command::Associate(associate, _)) => {
            let replied = associate
                .reply(Reply::CommandNotSupported, Address::unspecified())
                .await;

            let mut conn = match replied {
                Ok(conn) => conn,
                Err((err, mut conn)) => {
                    let _ = conn.shutdown().await;
                    return Err(Error::Io(err));
                }
            };

            let _ = conn.close().await;
        }
        Ok(Command::Bind(bind, _)) => {
            let replied = bind
                .reply(Reply::CommandNotSupported, Address::unspecified())
                .await;

            let mut conn = match replied {
                Ok(conn) => conn,
                Err((err, mut conn)) => {
                    let _ = conn.shutdown().await;
                    return Err(Error::Io(err));
                }
            };

            let _ = conn.close().await;
        }
        Ok(Command::Connect(connect, addr)) => {
            let target = match addr {
                Address::DomainAddress(domain, port) => {
                    let domain = String::from_utf8_lossy(&domain);
                    println!("Domain: {domain}");
                    SocketAddr::new(
                        lookup_host(format!("{}:{}", domain.to_string(), port))
                            .await
                            .unwrap()
                            .next()
                            .unwrap()
                            .ip(),
                        port,
                    )
                }
                Address::SocketAddress(addr) => addr,
            };

            {
                let replied = connect
                    .reply(Reply::Succeeded, Address::unspecified())
                    .await;

                let mut conn = match replied {
                    Ok(conn) => conn,
                    Err((err, mut conn)) => {
                        let _ = conn.shutdown().await;
                        return Err(Error::Io(err));
                    }
                };

                // pass conn_tcp_stream to wireguard handle tcp_stream
                let pf = PortForwardConfig {
                    source: SocketAddr::new(std::net::IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
                    destination: target,
                    protocol: crate::config::PortProtocol::Tcp,
                    remote: true,
                };

                let res = crate::tunnel::handle_tcp_port_forward(
                    conn.into_inner(),
                    &pf,
                    &std::net::IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                    &mut tcp_port_pool,
                    wg,
                    bus,
                )
                .await
                .unwrap();

                //let _ = conn.shutdown().await;
            }
        }
        Err((err, mut conn)) => {
            let _ = conn.shutdown().await;
            return Err(err);
        }
    }

    Ok(())
}