use async_trait::async_trait;
use core::str;
use hickory_server::authority::MessageResponseBuilder;
use hickory_server::proto::error::ProtoError;
use hickory_server::proto::op::Header;
use hickory_server::proto::op::ResponseCode;
use hickory_server::proto::rr::rdata::{A, AAAA};
use hickory_server::proto::rr::{LowerName, RData, Record};
use hickory_server::server::{
    Request, RequestHandler, ResponseHandler, ResponseInfo, ServerFuture,
};
use serde::Deserialize;
use std::collections::HashMap;
use std::fs;
use std::net::SocketAddr;
use std::net::{IpAddr, Ipv4Addr, SocketAddrV4};
use std::str::FromStr;
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::signal;
use trust_dns_resolver::config::Protocol;
use trust_dns_resolver::config::{NameServerConfig, ResolverConfig, ResolverOpts};
use trust_dns_resolver::TokioAsyncResolver;

#[derive(Deserialize)]
struct Config {
    port: u16,
    records: HashMap<String, Vec<String>>,
    servers: Vec<String>,
}

#[derive(Clone, Debug)]
pub struct Server {
    injections: HashMap<LowerName, Vec<IpAddr>>,
    resolver: Arc<TokioAsyncResolver>,
}

impl Default for Server {
    fn default() -> Self {
        let resolver =
            TokioAsyncResolver::tokio(ResolverConfig::google(), ResolverOpts::default()).unwrap();
        Server {
            injections: HashMap::new(),
            resolver: Arc::new(resolver),
        }
    }
}

impl Server {
    pub fn new(resolver_config: ResolverConfig) -> Self {
        let resolver = TokioAsyncResolver::tokio(resolver_config, ResolverOpts::default()).unwrap();
        Server {
            injections: HashMap::new(),
            resolver: Arc::new(resolver),
        }
    }

    pub fn inject_records(&mut self, name: &str, records: Vec<IpAddr>) -> Result<(), ProtoError> {
        let name = LowerName::from_str(name)?;
        self.injections.insert(name, records);
        Ok(())
    }

    pub async fn start(self, socket: UdpSocket) -> Result<(), ProtoError> {
        let mut server = ServerFuture::new(self);
        server.register_socket(socket);
        server.block_until_done().await?;
        Ok(())
    }
}

#[async_trait]
impl RequestHandler for Server {
    async fn handle_request<R: ResponseHandler>(
        &self,
        request: &Request,
        mut response_handler: R,
    ) -> ResponseInfo {
        let builder = MessageResponseBuilder::from_message_request(request);

        let mut header = Header::response_from_request(request.header());
        header.set_authoritative(true);

        let name = request.query().name();

        if let Some(entries) = self.injections.get(name) {
            let records: Vec<_> = entries
                .iter()
                .map(|entry| match entry {
                    IpAddr::V4(ipv4) => RData::A(A::from(*ipv4)),
                    IpAddr::V6(ipv6) => RData::AAAA(AAAA::from(*ipv6)),
                })
                .map(|rdata| Record::from_rdata(name.into(), 60, rdata))
                .collect();

            let response = builder.build(header, records.iter(), &[], &[], &[]);
            println!(
                "Response injected returning: {:?} for request from {:?}",
                response,
                request.src()
            );
            response_handler.send_response(response).await.unwrap()
        } else {
            // Forward the request to the public DNS server
            match self.resolver.lookup_ip(name.to_string()).await {
                Ok(lookup) => {
                    let records: Vec<_> = lookup
                        .iter()
                        .map(|ip| match ip {
                            IpAddr::V4(ipv4) => RData::A(A::from(ipv4)),
                            IpAddr::V6(ipv6) => RData::AAAA(AAAA::from(ipv6)),
                        })
                        .map(|rdata| Record::from_rdata(name.into(), 60, rdata))
                        .collect();

                    let response = builder.build(header, records.iter(), &[], &[], &[]);
                    response_handler.send_response(response).await.unwrap()
                }
                Err(_) => {
                    header.set_response_code(ResponseCode::ServFail);
                    let response = builder.build_no_records(header);
                    response_handler.send_response(response).await.unwrap()
                }
            }
        }
    }
}

type MainResult<T> = std::result::Result<T, Box<dyn std::error::Error>>;

#[tokio::main]
async fn main() -> MainResult<()> {
    let config_content = fs::read_to_string("config.toml")?;
    let config: Config = toml::from_str(&config_content)?;
    let mut resolver_config = ResolverConfig::new();
    config.servers.iter().for_each(|server| {
        let ip = IpAddr::from_str(server).unwrap();
        let udp_name_server = NameServerConfig {
            socket_addr: SocketAddr::new(ip, 53),
            protocol: Protocol::Udp,
            tls_dns_name: None,
            trust_nx_responses: true,
        };
        resolver_config.add_name_server(udp_name_server);
    });
    let mut server = Server::new(resolver_config.clone());
    println!("Resolver config: {:?}", resolver_config);

    for (name, ips) in config.records {
        let records: Result<Vec<IpAddr>, _> = ips.iter().map(|ip| IpAddr::from_str(ip)).collect();
        server.inject_records(&name, records?)?;
    }
    println!("Injected records: {:?}", server.injections);

    let addr = SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, config.port);
    let socket = UdpSocket::bind(&addr).await?;

    tokio::spawn(async move {
        server.start(socket).await.unwrap();
    });

    println!("Server running on {}, precess ctrl+c for quit...", addr);

    let ctrl_c = signal::ctrl_c();
    let _ = ctrl_c.await;
    println!("Received SIGINT, shutting down...");

    Ok(())
}
