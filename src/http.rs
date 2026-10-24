//! The upstream HTTP client settings shared by services, and bounded reads of its responses.

use std::error::Error;
use std::time::Duration;

/// The largest upstream response body a service should accept.
pub const MAX_RESPONSE_BYTES: usize = 4 << 20;

/// Installs the `ring` TLS provider for the whole process. reqwest is built without a bundled
/// provider, and a second install is not an error, so every client builder may call this.
pub fn install_crypto_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

/// A client builder with the settings of a single-owner server: no redirects, HTTP/1.1 only,
/// two idle connections per host for 30 s, a 10 s connect timeout. `extra_root_pem` adds
/// trusted roots, for tests that talk to a fake over TLS.
///
/// # Panics
///
/// When `extra_root_pem` is not valid PEM.
pub fn client_builder(extra_root_pem: Option<&[u8]>) -> reqwest::ClientBuilder {
    install_crypto_provider();

    let mut builder = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .http1_only()
        .pool_max_idle_per_host(2)
        .pool_idle_timeout(Duration::from_secs(30))
        .connect_timeout(Duration::from_secs(10));

    if let Some(pem) = extra_root_pem {
        let roots = reqwest::Certificate::from_pem_bundle(pem)
            .expect("the extra root certificates are valid PEM");

        builder = builder.tls_certs_merge(roots);
    }

    builder
}

/// The error and its causes on one line, without the URL (which may hold a secret).
pub fn describe(error: reqwest::Error) -> String {
    let error = error.without_url();
    let mut text = error.to_string();
    let mut source = error.source();

    while let Some(cause) = source {
        text.push_str(": ");
        text.push_str(&cause.to_string());
        source = cause.source();
    }

    text
}

/// Reads the body in chunks into a buffer that refuses to grow past `limit` bytes.
pub async fn read_capped(
    response: &mut reqwest::Response,
    limit: usize,
) -> Result<Vec<u8>, String> {
    let mut body = Vec::new();

    while let Some(chunk) = response.chunk().await.map_err(describe)? {
        if body.len() + chunk.len() > limit {
            return Err(format!("response larger than {limit} bytes"));
        }

        body.extend_from_slice(&chunk);
    }

    Ok(body)
}

#[cfg(test)]
mod tests {
    use axum::Router;
    use axum::routing::get;

    use super::*;

    async fn serve_body(size: usize) -> String {
        let router = Router::new().route("/body", get(move || async move { "x".repeat(size) }));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();

        tokio::spawn(async move {
            axum::serve(listener, router).await.unwrap();
        });

        format!("http://{address}/body")
    }

    #[tokio::test]
    async fn read_capped_refuses_over_limit() {
        let url = serve_body(2048).await;
        let client = client_builder(None).build().unwrap();
        let mut response = client.get(url).send().await.unwrap();

        let error = read_capped(&mut response, 1024).await.unwrap_err();

        assert!(error.contains("1024"), "{error}");
    }

    #[tokio::test]
    async fn read_capped_returns_body() {
        let url = serve_body(1024).await;
        let client = client_builder(None).build().unwrap();
        let mut response = client.get(url).send().await.unwrap();

        let body = read_capped(&mut response, 1024).await.unwrap();

        assert_eq!(body.len(), 1024);
    }
}
