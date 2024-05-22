use async_trait::async_trait;
use core::str;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddrV4};
use std::str::FromStr;
use tokio::net::UdpSocket;
use hickory_server::authority::MessageResponseBuilder;
use hickory_server::proto::error::ProtoError;
use hickory_server::proto::op::Header;
use hickory_server::proto::op::ResponseCode;
use hickory_server::proto::rr::rdata::{A, AAAA};
use hickory_server::proto::rr::{LowerName, RData, Record};
use tokio::signal;
use hickory_server::server::{
    Request, RequestHandler, ResponseHandler, ResponseInfo, ServerFuture,
};

#[derive(Clone, Debug, Default)]
pub struct Server {
    injections: HashMap<LowerName, Vec<IpAddr>>,
}

impl Server {
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
            response_handler.send_response(response).await.unwrap()
        } else {
            header.set_response_code(ResponseCode::ServFail);

            let response = builder.build_no_records(header);
            response_handler.send_response(response).await.unwrap()
        }
    }
}

type MainResult<T> = std::result::Result<T, Box<dyn std::error::Error>>;

#[tokio::main]
async fn main() -> MainResult<()> {
    let mut server = Server::default();

    let records = vec![IpAddr::V4(Ipv4Addr::LOCALHOST), IpAddr::V4(Ipv4Addr::new(10, 10, 1, 100))];
    server.inject_records("www.foo.com", records)?;

    let addr = SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 53);
    let socket = UdpSocket::bind(&addr).await?;

    tokio::spawn(async move {
        server.start(socket).await.unwrap();
    });

    // Point your DNS handling at `local_addr` and make requests
    println!("Server running on {}", addr);

    let ctrl_c = signal::ctrl_c();
    // 等待信号
    let _ = ctrl_c.await;
    println!("Received SIGINT, shutting down...");    

    Ok(()) // Explicitly return the unit type ()
}
