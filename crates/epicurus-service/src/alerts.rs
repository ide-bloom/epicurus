//! Alert channels: Discord, Slack, ntfy and a generic HMAC-signed JSON
//! webhook, with per-channel rate limiting. Toasts are raised by the tray
//! agent from pushed IPC events, and the Event Log is written synchronously
//! by the engine; both are gated by the same deduplication.

use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};

use epicurus_core::config::AlertsConfig;
use epicurus_core::incident::IncidentSummary;
use epicurus_core::ipc::ChannelKind;
use epicurus_core::scoring::{Reason, Severity};
use hmac::{Hmac, KeyInit, Mac};
use serde_json::json;
use sha2::Sha256;
use tokio::sync::{mpsc, oneshot};

/// Something worth telling the user about.
#[derive(Debug, Clone)]
pub enum AlertBody {
    /// Incident created or escalated.
    Incident {
        /// Summary.
        summary: IncidentSummary,
        /// Score reasons.
        reasons: Vec<Reason>,
        /// Leaf signer, if any.
        signer: Option<String>,
        /// Containment status line.
        containment: String,
        /// True if this is an escalation of an existing incident.
        escalated: bool,
    },
    /// A decoy was deleted, renamed or modified.
    Integrity {
        /// Path.
        path: String,
        /// Decoy id.
        decoy_id: String,
        /// What happened.
        change: String,
    },
}

/// A job for the dispatcher.
pub enum AlertJob {
    /// Fan out to every enabled webhook channel.
    Send {
        /// Content.
        body: AlertBody,
        /// Channel config snapshot.
        config: Box<AlertsConfig>,
        /// Hostname.
        host: String,
    },
    /// Send a test message to one channel and report back.
    Test {
        /// Channel.
        channel: ChannelKind,
        /// Channel config snapshot.
        config: Box<AlertsConfig>,
        /// Hostname.
        host: String,
        /// Result.
        reply: oneshot::Sender<Result<String, String>>,
    },
}

/// Deduplication and rate limiting, kept free of I/O so it can be tested.
#[derive(Debug, Default)]
pub struct Gate {
    seen: HashMap<String, Instant>,
    sent: HashMap<String, VecDeque<Instant>>,
}

impl Gate {
    /// True if `key` was not alerted within `window` (and records it).
    pub fn first_in_window(&mut self, key: &str, window: Duration, now: Instant) -> bool {
        self.seen
            .retain(|_, t| now.duration_since(*t) < window.max(Duration::from_secs(1)));
        if self.seen.contains_key(key) {
            return false;
        }
        self.seen.insert(key.to_string(), now);
        true
    }

    /// True if `channel` has sent fewer than `per_minute` messages in the
    /// last minute (and records this one).
    pub fn allow(&mut self, channel: &str, per_minute: u32, now: Instant) -> bool {
        let q = self.sent.entry(channel.to_string()).or_default();
        while q
            .front()
            .is_some_and(|t| now.duration_since(*t) >= Duration::from_secs(60))
        {
            q.pop_front();
        }
        if q.len() as u32 >= per_minute {
            return false;
        }
        q.push_back(now);
        true
    }
}

fn severity_color(s: Severity) -> u32 {
    match s {
        Severity::Critical => 0xE5484D,
        Severity::High => 0xF76B15,
        Severity::Medium => 0xFFB224,
        Severity::Low => 0x3E9BFF,
        Severity::Info => 0x8B95A5,
    }
}

/// Plain-text rendering used by ntfy and Slack fallbacks.
pub fn title_and_text(body: &AlertBody, host: &str) -> (String, String) {
    match body {
        AlertBody::Incident {
            summary: s,
            reasons,
            signer,
            containment,
            escalated,
        } => {
            let image = s.image.rsplit('\\').next().unwrap_or(&s.image);
            let title = format!(
                "[{}] {}Decoy credentials touched on {host}{}",
                s.severity.as_str().to_uppercase(),
                if *escalated { "Escalated: " } else { "" },
                if s.simulated { " (simulation)" } else { "" }
            );
            let top: Vec<String> = reasons
                .iter()
                .filter(|r| r.points != 0)
                .take(4)
                .map(|r| format!("- {}", r.detail))
                .collect();
            let text = format!(
                "{image} (PID {}) opened {} decoy(s) across {} categor{}. Score {}/100.\nSigner: {}\nContainment: {containment}\nIncident: {}\n{}",
                s.pid,
                s.decoys,
                s.categories.len(),
                if s.categories.len() == 1 { "y" } else { "ies" },
                s.score,
                signer.as_deref().unwrap_or("unsigned"),
                s.id,
                top.join("\n")
            );
            (title, text)
        }
        AlertBody::Integrity {
            path,
            decoy_id,
            change,
        } => (
            format!("[WARNING] Decoy {change} on {host}"),
            format!(
                "Decoy {decoy_id} at {path} was {change}. Epicurus logged it and will re-plant it."
            ),
        ),
    }
}

fn discord_payload(body: &AlertBody, host: &str) -> serde_json::Value {
    let (title, text) = title_and_text(body, host);
    let color = match body {
        AlertBody::Incident { summary, .. } => severity_color(summary.severity),
        AlertBody::Integrity { .. } => severity_color(Severity::Medium),
    };
    let mut fields = Vec::new();
    if let AlertBody::Incident {
        summary,
        signer,
        containment,
        ..
    } = body
    {
        fields.push(json!({"name": "Process", "value": format!("`{}` (PID {})", summary.image, summary.pid), "inline": false}));
        fields.push(json!({"name": "Score", "value": format!("{}/100 ({})", summary.score, summary.severity), "inline": true}));
        fields.push(json!({"name": "Decoys", "value": summary.decoys.to_string(), "inline": true}));
        fields.push(json!({"name": "Signer", "value": signer.clone().unwrap_or_else(|| "unsigned".into()), "inline": true}));
        fields.push(json!({"name": "Containment", "value": containment, "inline": false}));
        fields.push(
            json!({"name": "Incident", "value": format!("`{}`", summary.id), "inline": false}),
        );
    }
    json!({
        "username": "Epicurus",
        "allowed_mentions": {"parse": []},
        "embeds": [{
            "title": title,
            "description": text.lines().next().unwrap_or_default(),
            "color": color,
            "fields": fields,
            "timestamp": epicurus_core::timefmt::rfc3339(time::OffsetDateTime::now_utc()),
            "footer": {"text": format!("Epicurus {}", epicurus_core::VERSION)}
        }]
    })
}

fn slack_payload(body: &AlertBody, host: &str) -> serde_json::Value {
    let (title, text) = title_and_text(body, host);
    json!({
        "text": title,
        "blocks": [
            {"type": "header", "text": {"type": "plain_text", "text": title.chars().take(150).collect::<String>()}},
            {"type": "section", "text": {"type": "mrkdwn", "text": text.chars().take(2900).collect::<String>()}}
        ]
    })
}

fn generic_payload(body: &AlertBody, host: &str) -> serde_json::Value {
    let (title, text) = title_and_text(body, host);
    match body {
        AlertBody::Incident {
            summary,
            reasons,
            signer,
            containment,
            escalated,
        } => json!({
            "event": if *escalated { "incident.escalated" } else { "incident.created" },
            "host": host,
            "title": title,
            "text": text,
            "incident": summary,
            "reasons": reasons,
            "signer": signer,
            "containment": containment,
            "epicurus_version": epicurus_core::VERSION,
        }),
        AlertBody::Integrity {
            path,
            decoy_id,
            change,
        } => json!({
            "event": "decoy.integrity",
            "host": host,
            "title": title,
            "path": path,
            "decoy_id": decoy_id,
            "change": change,
            "epicurus_version": epicurus_core::VERSION,
        }),
    }
}

/// `sha256=<hex>` over `"{timestamp}.{body}"`.
pub fn sign(secret: &[u8], timestamp: i64, body: &[u8]) -> String {
    let Ok(mut mac) = <Hmac<Sha256> as KeyInit>::new_from_slice(secret) else {
        // HMAC accepts any key length; unreachable in practice.
        return String::new();
    };
    mac.update(timestamp.to_string().as_bytes());
    mac.update(b".");
    mac.update(body);
    format!("sha256={}", hex::encode(mac.finalize().into_bytes()))
}

fn ntfy_priority(body: &AlertBody) -> &'static str {
    match body {
        AlertBody::Incident { summary, .. } => match summary.severity {
            Severity::Critical => "5",
            Severity::High => "4",
            Severity::Medium => "3",
            _ => "2",
        },
        AlertBody::Integrity { .. } => "3",
    }
}

async fn deliver(
    client: &reqwest::Client,
    channel: ChannelKind,
    cfg: &AlertsConfig,
    body: &AlertBody,
    host: &str,
) -> Result<String, String> {
    let resp = match channel {
        ChannelKind::Discord => {
            let url = cfg.discord.url.open().map_err(|e| e.to_string())?;
            client
                .post(url)
                .json(&discord_payload(body, host))
                .send()
                .await
        }
        ChannelKind::Slack => {
            let url = cfg.slack.url.open().map_err(|e| e.to_string())?;
            client
                .post(url)
                .json(&slack_payload(body, host))
                .send()
                .await
        }
        ChannelKind::Ntfy => {
            let topic = cfg.ntfy.topic.open().map_err(|e| e.to_string())?;
            let (title, text) = title_and_text(body, host);
            let mut req = client
                .post(format!(
                    "{}/{}",
                    cfg.ntfy.server.trim_end_matches('/'),
                    topic
                ))
                .header(
                    "Title",
                    title
                        .chars()
                        .filter(|c| c.is_ascii() && !c.is_control())
                        .collect::<String>(),
                )
                .header("Priority", ntfy_priority(body))
                .header("Tags", "rotating_light")
                .body(text);
            if !cfg.ntfy.token.is_empty() {
                let token = cfg.ntfy.token.open().map_err(|e| e.to_string())?;
                req = req.bearer_auth(token);
            }
            req.send().await
        }
        ChannelKind::Generic => {
            let url = cfg.generic.url.open().map_err(|e| e.to_string())?;
            let payload =
                serde_json::to_vec(&generic_payload(body, host)).map_err(|e| e.to_string())?;
            let ts = time::OffsetDateTime::now_utc().unix_timestamp();
            let mut req = client
                .post(url)
                .header("Content-Type", "application/json")
                .header("X-Epicurus-Timestamp", ts.to_string());
            if !cfg.generic.secret.is_empty() {
                let secret = cfg.generic.secret.open().map_err(|e| e.to_string())?;
                req = req.header(
                    "X-Epicurus-Signature",
                    sign(secret.as_bytes(), ts, &payload),
                );
            }
            req.body(payload).send().await
        }
        ChannelKind::Toast | ChannelKind::EventLog => return Err("not a webhook channel".into()),
    };
    let resp = resp.map_err(|e| format!("request failed: {}", e.without_url()))?;
    let status = resp.status();
    if status.is_success() {
        Ok(format!("delivered (HTTP {})", status.as_u16()))
    } else {
        Err(format!("HTTP {}", status.as_u16()))
    }
}

fn enabled_channels(cfg: &AlertsConfig) -> Vec<ChannelKind> {
    let mut v = Vec::new();
    if cfg.discord.enabled && !cfg.discord.url.is_empty() {
        v.push(ChannelKind::Discord);
    }
    if cfg.slack.enabled && !cfg.slack.url.is_empty() {
        v.push(ChannelKind::Slack);
    }
    if cfg.ntfy.enabled && !cfg.ntfy.topic.is_empty() {
        v.push(ChannelKind::Ntfy);
    }
    if cfg.generic.enabled && !cfg.generic.url.is_empty() {
        v.push(ChannelKind::Generic);
    }
    v
}

/// The dispatcher task. Failures are reported back through `failures` so the
/// engine can log them to the Event Log.
pub async fn run_dispatcher(
    mut rx: mpsc::UnboundedReceiver<AlertJob>,
    failures: mpsc::UnboundedSender<String>,
) {
    let client = match reqwest::Client::builder()
        .timeout(Duration::from_secs(15))
        .user_agent(concat!("Epicurus/", env!("CARGO_PKG_VERSION")))
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            tracing::error!(error = %e, "could not build HTTP client; webhook alerts disabled");
            return;
        }
    };
    let mut gate = Gate::default();
    while let Some(job) = rx.recv().await {
        match job {
            AlertJob::Send { body, config, host } => {
                for ch in enabled_channels(&config) {
                    let key = format!("{ch:?}");
                    if !gate.allow(&key, config.max_per_minute, Instant::now()) {
                        tracing::warn!(channel = %key, "alert rate limit reached; dropping");
                        continue;
                    }
                    if let Err(e) = deliver(&client, ch, &config, &body, &host).await {
                        tracing::warn!(channel = %key, error = %e, "alert delivery failed");
                        let _ = failures.send(format!("{key}: {e}"));
                    }
                }
            }
            AlertJob::Test {
                channel,
                config,
                host,
                reply,
            } => {
                let body = AlertBody::Integrity {
                    path: r"C:\example\decoy".into(),
                    decoy_id: "test".into(),
                    change: "tested (this is a test message from Epicurus)".into(),
                };
                let _ = reply.send(deliver(&client, channel, &config, &body, &host).await);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use epicurus_core::catalog::Category;
    use epicurus_core::incident::IncidentStatus;

    fn summary() -> IncidentSummary {
        IncidentSummary {
            id: "inc_0123456789abcdef".into(),
            created_at: time::OffsetDateTime::now_utc(),
            severity: Severity::Critical,
            score: 95,
            status: IncidentStatus::AwaitingDecision,
            simulated: false,
            pid: 4242,
            image: r"C:\Users\a\AppData\Local\Temp\stealer.exe".into(),
            decoys: 4,
            categories: vec![Category::AiAgent, Category::Cloud, Category::Browser],
        }
    }

    #[test]
    fn dedupe_window() {
        let mut g = Gate::default();
        let t0 = Instant::now();
        assert!(g.first_in_window("k", Duration::from_secs(60), t0));
        assert!(!g.first_in_window("k", Duration::from_secs(60), t0 + Duration::from_secs(10)));
        assert!(g.first_in_window("k", Duration::from_secs(60), t0 + Duration::from_secs(61)));
        assert!(g.first_in_window("other", Duration::from_secs(60), t0));
    }

    #[test]
    fn rate_limit_per_minute() {
        let mut g = Gate::default();
        let t0 = Instant::now();
        for _ in 0..3 {
            assert!(g.allow("discord", 3, t0));
        }
        assert!(!g.allow("discord", 3, t0 + Duration::from_secs(5)));
        assert!(g.allow("slack", 3, t0));
        assert!(g.allow("discord", 3, t0 + Duration::from_secs(61)));
    }

    #[test]
    fn hmac_signature_matches_reference() {
        // Reference computed with Python's hmac module:
        // hmac.new(b"secret", b"1700000000.{}", hashlib.sha256).hexdigest()
        let sig = sign(b"secret", 1_700_000_000, b"{}");
        assert_eq!(
            sig,
            "sha256=b8569b78799ff9e3cbff0fc2d63a33a2b57f3282abd07c37ae5e8e7d79a5f163"
        );
        assert_ne!(sig, sign(b"secret2", 1_700_000_000, b"{}"));
        assert_ne!(sig, sign(b"secret", 1_700_000_001, b"{}"));
    }

    #[test]
    fn payloads_render() {
        let body = AlertBody::Incident {
            summary: summary(),
            reasons: vec![Reason {
                code: "x".into(),
                points: 40,
                detail: "Opened a decoy".into(),
            }],
            signer: None,
            containment: "Suspended 1 process".into(),
            escalated: false,
        };
        let d = discord_payload(&body, "host");
        assert_eq!(d["embeds"][0]["color"], 0xE5484D);
        assert!(
            d["embeds"][0]["title"]
                .as_str()
                .unwrap()
                .contains("CRITICAL")
        );
        let s = slack_payload(&body, "host");
        assert!(s["text"].as_str().unwrap().contains("host"));
        let g = generic_payload(&body, "host");
        assert_eq!(g["event"], "incident.created");
        assert_eq!(g["incident"]["pid"], 4242);
        assert_eq!(ntfy_priority(&body), "5");
    }

    #[test]
    fn disabled_or_unconfigured_channels_are_skipped() {
        let cfg = AlertsConfig::default();
        assert!(enabled_channels(&cfg).is_empty());
    }

    /// One captured HTTP request.
    struct Captured {
        request_line: String,
        headers: Vec<(String, String)>,
        body: Vec<u8>,
    }

    impl Captured {
        fn header(&self, name: &str) -> Option<&str> {
            self.headers
                .iter()
                .find(|(k, _)| k.eq_ignore_ascii_case(name))
                .map(|(_, v)| v.as_str())
        }
    }

    /// A one-shot HTTP/1.1 server on 127.0.0.1 that answers `status`.
    async fn one_shot_server(status: u16) -> (String, tokio::task::JoinHandle<Captured>) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut buf = Vec::new();
            let mut chunk = [0u8; 4096];
            let header_end = loop {
                let n = sock.read(&mut chunk).await.unwrap();
                assert!(n > 0, "connection closed before headers");
                buf.extend_from_slice(&chunk[..n]);
                if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                    break i + 4;
                }
            };
            let head = String::from_utf8_lossy(&buf[..header_end]).into_owned();
            let mut lines = head.split("\r\n");
            let request_line = lines.next().unwrap().to_string();
            let headers: Vec<(String, String)> = lines
                .filter_map(|l| {
                    l.split_once(':')
                        .map(|(k, v)| (k.trim().to_string(), v.trim().to_string()))
                })
                .collect();
            let len: usize = headers
                .iter()
                .find(|(k, _)| k.eq_ignore_ascii_case("content-length"))
                .map(|(_, v)| v.parse().unwrap())
                .unwrap_or(0);
            let mut body = buf[header_end..].to_vec();
            while body.len() < len {
                let n = sock.read(&mut chunk).await.unwrap();
                body.extend_from_slice(&chunk[..n]);
            }
            let reply =
                format!("HTTP/1.1 {status} X\r\ncontent-length: 0\r\nconnection: close\r\n\r\n");
            sock.write_all(reply.as_bytes()).await.unwrap();
            Captured {
                request_line,
                headers,
                body,
            }
        });
        (format!("http://{addr}"), handle)
    }

    fn client() -> reqwest::Client {
        let _ = rustls::crypto::ring::default_provider().install_default();
        reqwest::Client::builder().build().unwrap()
    }

    fn incident_body() -> AlertBody {
        AlertBody::Incident {
            summary: summary(),
            reasons: vec![Reason {
                code: "decoy_touched".into(),
                points: 40,
                detail: "Opened a decoy".into(),
            }],
            signer: None,
            containment: "Suspended 1 process(es)".into(),
            escalated: false,
        }
    }

    #[tokio::test]
    async fn generic_webhook_is_delivered_with_a_verifiable_hmac_signature() {
        let (base, server) = one_shot_server(200).await;
        let mut cfg = AlertsConfig::default();
        cfg.generic.enabled = true;
        cfg.generic.url = epicurus_core::protect::Protected::seal(&format!("{base}/hook")).unwrap();
        cfg.generic.secret =
            epicurus_core::protect::Protected::seal("a-sufficiently-long-secret").unwrap();

        let r = deliver(
            &client(),
            ChannelKind::Generic,
            &cfg,
            &incident_body(),
            "host",
        )
        .await;
        assert!(r.is_ok(), "{r:?}");
        let req = server.await.unwrap();
        assert_eq!(req.request_line, "POST /hook HTTP/1.1");
        let ts: i64 = req.header("x-epicurus-timestamp").unwrap().parse().unwrap();
        let sig = req.header("x-epicurus-signature").unwrap();
        // The receiver recomputes the signature over "<timestamp>.<body>".
        assert_eq!(sig, sign(b"a-sufficiently-long-secret", ts, &req.body));
        let json: serde_json::Value = serde_json::from_slice(&req.body).unwrap();
        assert_eq!(json["event"], "incident.created");
        assert_eq!(json["incident"]["pid"], 4242);
    }

    #[tokio::test]
    async fn discord_and_ntfy_payloads_reach_the_endpoint() {
        let (base, server) = one_shot_server(204).await;
        let mut cfg = AlertsConfig::default();
        cfg.discord.url =
            epicurus_core::protect::Protected::seal(&format!("{base}/api/webhooks/1/x")).unwrap();
        let r = deliver(
            &client(),
            ChannelKind::Discord,
            &cfg,
            &incident_body(),
            "host",
        )
        .await;
        assert!(r.is_ok(), "{r:?}");
        let req = server.await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&req.body).unwrap();
        assert_eq!(json["username"], "Epicurus");
        assert!(json["embeds"][0]["fields"].as_array().unwrap().len() >= 5);

        let (base, server) = one_shot_server(200).await;
        let mut cfg = AlertsConfig::default();
        cfg.ntfy.server = base;
        cfg.ntfy.topic = epicurus_core::protect::Protected::seal("epicurus-test-topic").unwrap();
        cfg.ntfy.token = epicurus_core::protect::Protected::seal("tk_test").unwrap();
        let r = deliver(&client(), ChannelKind::Ntfy, &cfg, &incident_body(), "host").await;
        assert!(r.is_ok(), "{r:?}");
        let req = server.await.unwrap();
        assert_eq!(req.request_line, "POST /epicurus-test-topic HTTP/1.1");
        assert_eq!(req.header("priority"), Some("5"));
        assert_eq!(req.header("authorization"), Some("Bearer tk_test"));
        assert!(String::from_utf8_lossy(&req.body).contains("PID 4242"));
    }

    #[tokio::test]
    async fn http_errors_are_reported_not_swallowed() {
        let (base, server) = one_shot_server(500).await;
        let mut cfg = AlertsConfig::default();
        cfg.slack.url =
            epicurus_core::protect::Protected::seal(&format!("{base}/services/x")).unwrap();
        let r = deliver(
            &client(),
            ChannelKind::Slack,
            &cfg,
            &incident_body(),
            "host",
        )
        .await;
        assert_eq!(r, Err("HTTP 500".to_string()));
        let _ = server.await;
    }
}
