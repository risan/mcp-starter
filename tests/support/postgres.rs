//! A throwaway Postgres 17 over TLS in a local container. Without Docker the tests that use it
//! print a skip line and pass, except under `CI`, where they fail.

use std::process::Command;
use std::sync::Arc;
use std::time::{Duration, Instant};

use mcp_starter::oauth::postgres::{PgStore, SCHEMA};
use mcp_starter::test_support::tls::{CA_PEM, LEAF_KEY, LEAF_PEM};
use rustls::RootCertStore;
use rustls::pki_types::CertificateDer;
use rustls::pki_types::pem::PemObject;
use tokio_postgres::Client;
use tokio_postgres_rustls::MakeRustlsConnect;

const IMAGE: &str = "postgres:17-alpine";
const PASSWORD: &str = "superuser-pw";
const READY_LIMIT: Duration = Duration::from_secs(60);

// Docker hands the certificate and key over as environment values, so no bind mount's owner or
// mode can stop Postgres from reading them.
const START_SCRIPT: &str = r#"printf '%s' "$TLS_CERT" > /tmp/server.crt \
&& printf '%s' "$TLS_KEY" > /tmp/server.key \
&& chown postgres /tmp/server.crt /tmp/server.key \
&& chmod 600 /tmp/server.key \
&& exec docker-entrypoint.sh postgres -c ssl=on \
    -c ssl_cert_file=/tmp/server.crt -c ssl_key_file=/tmp/server.key"#;

pub struct Postgres {
    id: String,
    pub port: u16,
}

impl Postgres {
    /// A started container with the crate's schema applied. `None` (after a skip line) when
    /// Docker is not running, unless `CI` is set.
    pub async fn ready() -> Option<Postgres> {
        let postgres = Postgres::start()?;

        postgres
            .superuser()
            .await
            .batch_execute(SCHEMA)
            .await
            .unwrap();

        Some(postgres)
    }

    fn start() -> Option<Postgres> {
        let docker_runs = Command::new("docker")
            .arg("info")
            .output()
            .is_ok_and(|output| output.status.success());

        if !docker_runs {
            assert!(
                std::env::var_os("CI").is_none(),
                "Docker must run under CI for the database tests"
            );
            eprintln!("skipped: Docker is not running, so a database test did not run");

            return None;
        }

        let id = docker(&[
            "run",
            "-d",
            "--rm",
            "--label",
            "mcp-starter-test",
            "-p",
            "127.0.0.1::5432",
            "-e",
            &format!("POSTGRES_PASSWORD={PASSWORD}"),
            "-e",
            &format!("TLS_CERT={}", String::from_utf8_lossy(LEAF_PEM)),
            "-e",
            &format!("TLS_KEY={}", String::from_utf8_lossy(LEAF_KEY)),
            "--entrypoint",
            "sh",
            IMAGE,
            "-c",
            START_SCRIPT,
        ]);
        let mut postgres = Postgres {
            id: id.trim().to_string(),
            port: 0,
        };
        let mapping = docker(&["port", &postgres.id, "5432/tcp"]);

        postgres.port = mapping
            .lines()
            .next()
            .and_then(|line| line.rsplit(':').next())
            .and_then(|port| port.trim().parse().ok())
            .unwrap_or_else(|| panic!("no published port in {mapping:?}"));

        Some(postgres)
    }

    pub fn config(&self) -> tokio_postgres::Config {
        let mut config = tokio_postgres::Config::new();

        config
            .host("127.0.0.1")
            .port(self.port)
            .user("postgres")
            .password(PASSWORD)
            .dbname("postgres")
            .ssl_mode(tokio_postgres::config::SslMode::Require);

        config
    }

    /// A TLS connection that trusts the test CA, retried until the server is ready.
    pub async fn superuser(&self) -> Client {
        let config = self.config();
        let started = Instant::now();

        loop {
            match config.connect(test_tls()).await {
                Ok((client, connection)) => {
                    tokio::spawn(connection);

                    return client;
                }
                Err(_) if started.elapsed() < READY_LIMIT => {
                    tokio::time::sleep(Duration::from_millis(250)).await;
                }
                Err(error) => panic!("Postgres never accepted the connection: {error:?}"),
            }
        }
    }

    pub fn store(&self) -> PgStore {
        PgStore::new(self.config(), test_roots())
    }

    /// A store with its own permit wait and operation deadline, so the tests of the limits
    /// do not take ten seconds.
    pub fn store_with_limits(&self, permit_wait: Duration, deadline: Duration) -> PgStore {
        PgStore::with_limits(self.config(), test_roots(), permit_wait, deadline)
    }
}

impl Drop for Postgres {
    fn drop(&mut self) {
        let _ = Command::new("docker").args(["rm", "-f", &self.id]).output();
    }
}

fn docker(args: &[&str]) -> String {
    let output = Command::new("docker")
        .args(args)
        .output()
        .expect("docker runs");

    assert!(
        output.status.success(),
        "docker {} failed: {}",
        args[0],
        String::from_utf8_lossy(&output.stderr)
    );

    String::from_utf8(output.stdout).unwrap()
}

pub fn test_roots() -> RootCertStore {
    let mut roots = RootCertStore::empty();

    for certificate in CertificateDer::pem_slice_iter(CA_PEM) {
        roots.add(certificate.unwrap()).unwrap();
    }

    roots
}

fn test_tls() -> MakeRustlsConnect {
    let config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_root_certificates(test_roots())
    .with_no_client_auth();

    MakeRustlsConnect::new(config)
}
