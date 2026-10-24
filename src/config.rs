//! Configuration read from the environment, under the service's own prefix.

use std::fmt;
use std::path::PathBuf;

use jiff::Timestamp;
use jiff::tz::TimeZone;

use crate::ServiceInfo;

/// The settings every service shares.
#[derive(Clone)]
pub struct Config {
    /// The https origin clients reach the server at; empty when not set and not required.
    pub public_url: String,
    /// The address to listen on.
    pub listen: String,
    /// The directory holding the state file.
    pub data_dir: PathBuf,
    /// The zone that decides what "today" is.
    pub tz: TimeZone,
}

/// A setting that cannot be used.
#[derive(Debug)]
pub struct ConfigError(String);

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for ConfigError {}

impl Config {
    /// Reads `<env_prefix>PUBLIC_URL`, `LISTEN`, `DATA_DIR` and `TZ` through `getenv`, which
    /// returns an empty string for an unset name. The public URL is required only when
    /// `require_public_url` is set (for `serve`); the CLI commands run without it.
    pub fn load(
        info: &ServiceInfo,
        getenv: &dyn Fn(&str) -> String,
        require_public_url: bool,
    ) -> Result<Config, ConfigError> {
        let public_url_name = format!("{}PUBLIC_URL", info.env_prefix);
        let public_url = getenv(&public_url_name);

        if !public_url.is_empty() || require_public_url {
            validate_public_url(&public_url_name, &public_url)?;
        }

        let tz_name = format!("{}TZ", info.env_prefix);
        let zone = value_or(getenv(&tz_name), info.default_tz);
        let tz = TimeZone::get(&zone)
            .map_err(|error| ConfigError(format!("{tz_name} {zone:?}: {error}")))?;

        Ok(Config {
            public_url,
            listen: value_or(
                getenv(&format!("{}LISTEN", info.env_prefix)),
                info.default_listen,
            ),
            data_dir: PathBuf::from(value_or(
                getenv(&format!("{}DATA_DIR", info.env_prefix)),
                info.default_data_dir,
            )),
            tz,
        })
    }

    /// The current date in the configured zone, as YYYY-MM-DD.
    pub fn today(&self, now: Timestamp) -> String {
        now.to_zoned(self.tz.clone()).date().to_string()
    }
}

fn validate_public_url(name: &str, raw: &str) -> Result<(), ConfigError> {
    if raw.is_empty() {
        return Err(ConfigError(format!(
            "{name} is required (an https origin such as https://mcp.example.com)"
        )));
    }

    let is_origin = raw.strip_prefix("https://").is_some_and(|authority| {
        !authority.is_empty()
            && !authority
                .chars()
                .any(|c| matches!(c, '/' | '?' | '#' | '@') || c.is_whitespace())
    }) && reqwest::Url::parse(raw).is_ok_and(|url| url.host_str().is_some());

    if !is_origin {
        return Err(ConfigError(format!(
            "{name} {raw:?} must be an https origin with no path or trailing slash, such as https://mcp.example.com"
        )));
    }

    Ok(())
}

fn value_or(value: String, fallback: &str) -> String {
    if value.is_empty() {
        return fallback.to_string();
    }

    value
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;

    const INFO: ServiceInfo = ServiceInfo {
        command: "example-mcp",
        display_name: "Example",
        env_prefix: "EXAMPLE_MCP_",
        default_listen: "127.0.0.1:8090",
        default_data_dir: "/var/lib/example-mcp",
        default_tz: "Asia/Jakarta",
        scope: "example",
        favicon: &[],
    };

    fn env(pairs: &[(&str, &str)]) -> impl Fn(&str) -> String {
        let map: HashMap<String, String> = pairs
            .iter()
            .map(|(key, value)| (key.to_string(), value.to_string()))
            .collect();

        move |key| map.get(key).cloned().unwrap_or_default()
    }

    #[test]
    fn defaults() {
        let config = Config::load(&INFO, &env(&[]), false).unwrap();

        assert_eq!(config.public_url, "");
        assert_eq!(config.listen, "127.0.0.1:8090");
        assert_eq!(config.data_dir, PathBuf::from("/var/lib/example-mcp"));
        assert_eq!(config.tz.iana_name(), Some("Asia/Jakarta"));
    }

    #[test]
    fn overrides_are_read() {
        let config = Config::load(
            &INFO,
            &env(&[
                ("EXAMPLE_MCP_PUBLIC_URL", "https://mcp.example.com"),
                ("EXAMPLE_MCP_LISTEN", "127.0.0.1:9000"),
                ("EXAMPLE_MCP_DATA_DIR", "/tmp/data"),
                ("EXAMPLE_MCP_TZ", "Europe/Amsterdam"),
            ]),
            true,
        )
        .unwrap();

        assert_eq!(config.public_url, "https://mcp.example.com");
        assert_eq!(config.listen, "127.0.0.1:9000");
        assert_eq!(config.data_dir, PathBuf::from("/tmp/data"));
        assert_eq!(config.tz.iana_name(), Some("Europe/Amsterdam"));
    }

    #[test]
    fn public_url_validation() {
        let rejected = [
            "http://mcp.example.com",
            "https://mcp.example.com/",
            "https://mcp.example.com/mcp",
            "https://mcp.example.com?x=1",
            "https://mcp.example.com#frag",
            "https://user@mcp.example.com",
            "https://",
            "https://:8443",
            "https://mcp.example.com:abc",
            "mcp.example.com",
        ];

        for url in rejected {
            let result = Config::load(&INFO, &env(&[("EXAMPLE_MCP_PUBLIC_URL", url)]), false);

            assert!(result.is_err(), "{url} should be rejected");
        }

        let accepted = ["https://mcp.example.com", "https://mcp.example.com:8443"];

        for url in accepted {
            let result = Config::load(&INFO, &env(&[("EXAMPLE_MCP_PUBLIC_URL", url)]), true);

            assert!(result.is_ok(), "{url} should be accepted");
        }
    }

    #[test]
    fn empty_public_url_is_an_error_only_for_serve() {
        assert!(Config::load(&INFO, &env(&[]), false).is_ok());

        let error = Config::load(&INFO, &env(&[]), true).err().unwrap();

        assert!(
            error
                .to_string()
                .contains("EXAMPLE_MCP_PUBLIC_URL is required")
        );
    }

    #[test]
    fn unknown_zone_is_an_error() {
        let error = Config::load(&INFO, &env(&[("EXAMPLE_MCP_TZ", "Mars/Olympus")]), false)
            .err()
            .unwrap();

        assert!(error.to_string().contains("EXAMPLE_MCP_TZ"));
    }

    #[test]
    fn today_in_zone() {
        let config =
            Config::load(&INFO, &env(&[("EXAMPLE_MCP_TZ", "Asia/Jakarta")]), false).unwrap();
        let now: Timestamp = "2026-10-23T18:30:00Z".parse().unwrap();

        assert_eq!(config.today(now), "2026-10-24");
    }

    #[test]
    fn prefix_is_the_services_own() {
        let config = Config::load(
            &INFO,
            &env(&[
                ("OTHER_MCP_PUBLIC_URL", "https://other.example.com"),
                ("OTHER_MCP_LISTEN", "127.0.0.1:9999"),
                ("OTHER_MCP_DATA_DIR", "/tmp/other"),
                ("OTHER_MCP_TZ", "Europe/Amsterdam"),
            ]),
            false,
        )
        .unwrap();

        assert_eq!(config.public_url, "");
        assert_eq!(config.listen, "127.0.0.1:8090");
        assert_eq!(config.data_dir, PathBuf::from("/var/lib/example-mcp"));
        assert_eq!(config.tz.iana_name(), Some("Asia/Jakarta"));
    }
}
