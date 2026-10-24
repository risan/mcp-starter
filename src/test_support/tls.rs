//! A throwaway TLS chain and an HTTPS server, for tests of the upstream client.

use std::sync::Arc;

use axum::Router;
use tokio::net::TcpListener;

/// The test CA certificate (PEM). Hand it to [`crate::http::client_builder`].
pub const CA_PEM: &[u8] = include_bytes!("tls/ca.pem");
/// The leaf certificate (PEM) for `localhost` and `127.0.0.1`, signed by the CA.
pub const LEAF_PEM: &[u8] = include_bytes!("tls/leaf.pem");
/// The leaf's private key (PEM).
pub const LEAF_KEY: &[u8] = include_bytes!("tls/leaf.key");

/// Accepts TCP connections and completes the TLS handshake before handing them to axum.
struct TlsListener {
    tcp: TcpListener,
    acceptor: tokio_rustls::TlsAcceptor,
}

impl axum::serve::Listener for TlsListener {
    type Io = tokio_rustls::server::TlsStream<tokio::net::TcpStream>;
    type Addr = std::net::SocketAddr;

    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        loop {
            let Ok((stream, address)) = self.tcp.accept().await else {
                continue;
            };

            if let Ok(tls) = self.acceptor.accept(stream).await {
                return (tls, address);
            }
        }
    }

    fn local_addr(&self) -> std::io::Result<Self::Addr> {
        self.tcp.local_addr()
    }
}

fn tls_acceptor(certificate_pem: &[u8], key_pem: &[u8]) -> tokio_rustls::TlsAcceptor {
    use rustls::pki_types::pem::PemObject;
    use rustls::pki_types::{CertificateDer, PrivateKeyDer};

    let certificates: Vec<CertificateDer<'static>> =
        CertificateDer::pem_slice_iter(certificate_pem)
            .collect::<Result<_, _>>()
            .unwrap();
    let key = PrivateKeyDer::from_pem_slice(key_pem).unwrap();
    let config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certificates, key)
        .unwrap();

    tokio_rustls::TlsAcceptor::from(Arc::new(config))
}

/// Serves `router` over HTTPS with the test chain on a free loopback port and returns the
/// base URL (`https://127.0.0.1:<port>`). The server runs until the runtime ends.
pub async fn serve_https(router: Router) -> String {
    super::install_crypto_provider();

    let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = tcp.local_addr().unwrap();
    let listener = TlsListener {
        tcp,
        acceptor: tls_acceptor(LEAF_PEM, LEAF_KEY),
    };

    tokio::spawn(async move {
        axum::serve(listener, router).await.unwrap();
    });

    format!("https://{address}")
}
