mod cache;
mod metrics;
mod server;

use ipnetwork::IpNetwork;
use std::net::IpAddr;

use clap::Parser;
use std::sync::Arc;
use tracing::info;
use tracing_subscriber::EnvFilter;

#[derive(Parser, Debug, Clone)]
#[command(author, version, about, long_about = None)]
pub struct Config {
    /// Listen host
    #[arg(long, default_value = "127.0.0.1")]
    pub listen_host: String,

    /// Listen port
    #[arg(long, default_value_t = 9899)]
    pub listen_port: u16,

    /// Metrics endpoint
    #[arg(long, default_value = "/metrics")]
    pub metrics_endpoint: String,

    /// Metrics prefix
    #[arg(long, default_value = "login_counter")]
    pub metrics_prefix: String,

    /// Scrape interval in milliseconds (ie, cache duration)
    #[arg(long, default_value_t = 5000)]
    pub scrape_interval: u64,

    /// Optional comma-separated list of allowed IP or CIDR addresses (if not provided, all IPs are allowed)
    #[arg(long, value_parser = validate_allowed_ips)]
    pub allowed_ips: Option<String>,

    /// Don't deduplicate user sessions per type, instead counting every session
    #[arg(long, action)]
    pub allow_duplicated_user_sessions: bool,
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    // Initialize logging
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    let config = Config::parse();
    info!("Starting login-counter exporter with config: {:?}", config);

    let config = Arc::new(config);
    let cache = cache::new_cache();

    server::run(config, cache).await
}

/// Validates a comma‑separated list of allowed IPs or CIDR ranges.
/// If each token is either a valid IpNetwork (CIDR) or a valid IpAddr,
/// the function returns Ok(String) with the original string; otherwise, it returns an error.
fn validate_allowed_ips(s: &str) -> Result<String, String> {
    let tokens: Vec<&str> = s
        .split(',')
        .map(|token| token.trim())
        .filter(|token| !token.is_empty())
        .collect();

    for token in tokens {
        // Try parsing as an IpNetwork (CIDR)
        if token.parse::<IpNetwork>().is_err() && token.parse::<IpAddr>().is_err() {
            return Err(format!(
                "Invalid allowed IP entry '{}': must be a valid IP or CIDR network",
                token
            ));
        }
    }
    Ok(s.to_string())
}
