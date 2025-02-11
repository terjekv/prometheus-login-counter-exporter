use crate::cache::{Cache, CachedMetrics};
use crate::metrics;
use crate::Config;
use actix_web::{web, App, HttpRequest, HttpResponse, HttpServer, Responder};
use ipnetwork::IpNetwork;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Instant;
use tracing::{debug, info, warn};

pub async fn run(config: Arc<Config>, cache: Cache) -> std::io::Result<()> {
    let host = config.listen_host.clone();
    let port = config.listen_port;
    let addr = format!("{}:{}", host, port);
    info!("Listening on http://{}", addr);

    // Wrap config and cache in Actix Web shared data.
    let config_data = web::Data::new(config.clone());
    let cache_data = web::Data::new(cache);
    let metrics_endpoint = config.metrics_endpoint.clone();

    HttpServer::new(move || {
        App::new()
            .app_data(config_data.clone())
            .app_data(cache_data.clone())
            // Register the metrics endpoint (e.g. "/metrics")
            .service(web::resource(&metrics_endpoint).route(web::get().to(metrics_handler)))
    })
    .workers(1)
    .bind(addr)?
    .run()
    .await
}

async fn metrics_handler(
    req: HttpRequest,
    config: web::Data<Arc<Config>>,
    cache: web::Data<Cache>,
) -> impl Responder {
    // Log the remote IP
    if let Some(peer_addr) = req.peer_addr() {
        debug!("Incoming request from: {}", peer_addr);
        // If an allow list is configured, check that the peer's IP is allowed.
        if !is_allowed(&peer_addr.ip(), &config.allowed_ips) {
            warn!("Access denied for IP: {}", peer_addr.ip());
            return HttpResponse::Forbidden()
                .content_type("text/plain")
                .body("Forbidden");
        }
    } else {
        debug!("Incoming request with unknown remote host");
    }

    let now = Instant::now();

    {
        let cache_guard = cache.lock().unwrap();
        if let Some(cached) = &*cache_guard {
            if cached.is_valid(config.scrape_interval) {
                debug!("Returning cached metrics");
                return text_plain_ok(cached.metrics.clone());
            }
        }
    }

    let sessions = match metrics::scrape_sessions() {
        Ok(s) => s,
        Err(err_msg) => {
            warn!("Error getting metrics: {}", err_msg);
            return text_plain_server_error(err_msg);
        }
    };

    let metrics_str = sessions.build_metrics_string(
        &config.metrics_prefix,
        config.allow_duplicated_user_sessions,
    );

    {
        let mut cache_guard = cache.lock().unwrap();
        *cache_guard = Some(CachedMetrics {
            timestamp: now,
            metrics: metrics_str.clone(),
        });
        debug!(
            "Cached metrics for another {} milliseconds",
            config.scrape_interval
        );
    }

    text_plain_ok(metrics_str)
}

/// Check if the given IP address is allowed based on the provided list.
///
/// * `ip` - The IP address to check.
/// * `allowed_ips` - An optional comma-separated list of allowed IP addresses or CIDR networks.
///
/// Each token in `allowed_ips` may be either a single IP (e.g., "127.0.0.1")
/// or a CIDR network (e.g., "192.168.1.0/24"). If no allow list is provided, all IPs are allowed.
///
/// Returns true if the allowed_ips list is empty or contains the given IP address.
fn is_allowed(ip: &IpAddr, allowed_ips: &Option<String>) -> bool {
    if let Some(allowed_list) = allowed_ips {
        // If the list is empty, all IPs are allowed, this is in case someone
        // sets an empty string as the allowed_ips value.
        if allowed_list.trim().is_empty() {
            return true;
        }

        let allowed: Vec<&str> = allowed_list
            .split(',')
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
            .collect();
        allowed.iter().any(|&entry| {
            if let Ok(net) = entry.parse::<IpNetwork>() {
                net.contains(*ip)
            } else if let Ok(allowed_ip) = entry.parse::<IpAddr>() {
                allowed_ip == *ip
            } else {
                warn!("Invalid allowed IP entry after validating? {}", entry);
                false
            }
        })
    } else {
        true
    }
}
fn text_plain_server_error(body: String) -> HttpResponse {
    HttpResponse::InternalServerError()
        .content_type("text/plain")
        .body(body)
}

fn text_plain_ok(body: String) -> HttpResponse {
    HttpResponse::Ok().content_type("text/plain").body(body)
}
