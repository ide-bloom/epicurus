//! STIX 2.1 bundle: the image (file SCO with SHA-256), the process, its
//! remote endpoints, an observed-data SDO tying them together, and
//! indicators for the hash and remote addresses.

use serde_json::{Value, json};

use crate::Result;
use crate::generators::random_uuid;
use crate::incident::Incident;
use crate::timefmt::rfc3339;

fn sid(kind: &str) -> String {
    format!("{kind}--{}", random_uuid())
}

/// Splits `"1.2.3.4:443"` / `"[::1]:443"` into address and port.
pub fn split_endpoint(s: &str) -> Option<(String, u16)> {
    if let Some(rest) = s.strip_prefix('[') {
        let (addr, port) = rest.split_once("]:")?;
        return Some((addr.to_string(), port.parse().ok()?));
    }
    let (addr, port) = s.rsplit_once(':')?;
    Some((addr.to_string(), port.parse().ok()?))
}

/// Builds the bundle as pretty JSON.
pub fn bundle(inc: &Incident) -> Result<String> {
    let now = rfc3339(inc.updated_at);
    let created = rfc3339(inc.created_at);
    let identity = sid("identity");
    let p = &inc.process;
    let mut objects: Vec<Value> = vec![json!({
        "type": "identity", "spec_version": "2.1", "id": identity,
        "created": created, "modified": created,
        "name": "Epicurus", "identity_class": "system",
        "description": format!("Epicurus {} on {}", inc.epicurus_version, inc.host)
    })];
    let mut refs = Vec::new();

    let file_id = sid("file");
    let mut file = json!({
        "type": "file", "spec_version": "2.1", "id": file_id,
        "name": p.image_path.rsplit('\\').next().unwrap_or(&p.image_path),
    });
    if let Some(h) = &p.image_sha256 {
        file["hashes"] = json!({ "SHA-256": h });
    }
    if let Some(sz) = p.image_size {
        file["size"] = json!(sz);
    }
    objects.push(file);
    refs.push(file_id.clone());

    let proc_id = sid("process");
    let mut process = json!({
        "type": "process", "spec_version": "2.1", "id": proc_id,
        "pid": p.pid, "image_ref": file_id,
    });
    if let Some(c) = &p.command_line {
        process["command_line"] = json!(c);
    }
    if let Some(t) = p.start_time {
        process["created_time"] = json!(rfc3339(t));
    }
    objects.push(process);
    refs.push(proc_id);

    let mut remote_addrs = Vec::new();
    for c in &p.network {
        let Some((addr, port)) = split_endpoint(&c.remote) else {
            continue;
        };
        if addr.is_empty() || addr == "0.0.0.0" || addr == "::" {
            continue;
        }
        let v6 = addr.contains(':');
        let addr_id = sid(if v6 { "ipv6-addr" } else { "ipv4-addr" });
        objects.push(json!({
            "type": if v6 { "ipv6-addr" } else { "ipv4-addr" },
            "spec_version": "2.1", "id": addr_id, "value": addr
        }));
        let nt_id = sid("network-traffic");
        objects.push(json!({
            "type": "network-traffic", "spec_version": "2.1", "id": nt_id,
            "dst_ref": addr_id, "dst_port": port,
            "protocols": [if c.protocol.starts_with("udp") { "udp" } else { "tcp" }]
        }));
        refs.push(addr_id);
        refs.push(nt_id);
        remote_addrs.push((addr, v6));
    }

    objects.push(json!({
        "type": "observed-data", "spec_version": "2.1", "id": sid("observed-data"),
        "created_by_ref": identity, "created": created, "modified": now,
        "first_observed": inc.touches.first().map(|t| rfc3339(t.at)).unwrap_or_else(|| created.clone()),
        "last_observed": inc.touches.last().map(|t| rfc3339(t.at)).unwrap_or_else(|| now.clone()),
        "number_observed": inc.touches.len().max(1),
        "object_refs": refs,
    }));

    let labels = if inc.simulated {
        json!(["epicurus-simulation"])
    } else {
        json!(["epicurus"])
    };
    if let Some(h) = &p.image_sha256 {
        objects.push(json!({
            "type": "indicator", "spec_version": "2.1", "id": sid("indicator"),
            "created_by_ref": identity, "created": created, "modified": now,
            "name": "Infostealer image hash",
            "description": format!("Process opened {} Epicurus decoy credential(s) (score {}/100, {}).", inc.distinct_decoys(), inc.score, inc.severity),
            "indicator_types": ["malicious-activity"],
            "pattern": format!("[file:hashes.'SHA-256' = '{h}']"),
            "pattern_type": "stix", "valid_from": created, "labels": labels,
        }));
    }
    for (addr, v6) in remote_addrs {
        objects.push(json!({
            "type": "indicator", "spec_version": "2.1", "id": sid("indicator"),
            "created_by_ref": identity, "created": created, "modified": now,
            "name": "Infostealer network endpoint",
            "description": "Remote endpoint held by the process at triage time.",
            "indicator_types": ["malicious-activity"],
            "pattern": format!("[{}:value = '{}']", if v6 { "ipv6-addr" } else { "ipv4-addr" }, addr.replace('\'', "")),
            "pattern_type": "stix", "valid_from": created, "labels": labels,
        }));
    }

    let b = json!({ "type": "bundle", "id": sid("bundle"), "objects": objects });
    Ok(serde_json::to_string_pretty(&b)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::incident::{NetConnection, ProcessProfile};
    use time::OffsetDateTime;

    #[test]
    fn bundle_contains_hash_process_and_network_indicators() {
        let p = ProcessProfile {
            pid: 4242,
            image_path: r"C:\Users\a\AppData\Local\Temp\x.exe".into(),
            image_sha256: Some("ab".repeat(32)),
            network: vec![
                NetConnection {
                    protocol: "tcp".into(),
                    local: "10.0.0.2:5000".into(),
                    remote: "203.0.113.9:443".into(),
                    state: "ESTABLISHED".into(),
                },
                NetConnection {
                    protocol: "tcp6".into(),
                    local: "[::1]:1".into(),
                    remote: "[2001:db8::1]:8443".into(),
                    state: "ESTABLISHED".into(),
                },
            ],
            ..Default::default()
        };
        let inc = Incident::new(p, OffsetDateTime::now_utc(), "h".into());
        let v: Value = serde_json::from_str(&bundle(&inc).unwrap()).unwrap();
        assert_eq!(v["type"], "bundle");
        let objs = v["objects"].as_array().unwrap();
        let types: Vec<&str> = objs.iter().map(|o| o["type"].as_str().unwrap()).collect();
        for t in [
            "identity",
            "file",
            "process",
            "ipv4-addr",
            "ipv6-addr",
            "network-traffic",
            "observed-data",
            "indicator",
        ] {
            assert!(types.contains(&t), "missing {t}");
        }
        assert!(
            objs.iter()
                .any(|o| o["pattern"].as_str().is_some_and(|p| p.contains("SHA-256")))
        );
        assert!(objs.iter().all(|o| {
            o["id"]
                .as_str()
                .unwrap()
                .starts_with(o["type"].as_str().unwrap())
        }));
        assert_eq!(objs.iter().filter(|o| o["type"] == "indicator").count(), 3);
    }

    #[test]
    fn endpoint_parsing() {
        assert_eq!(split_endpoint("1.2.3.4:80"), Some(("1.2.3.4".into(), 80)));
        assert_eq!(split_endpoint("[::1]:443"), Some(("::1".into(), 443)));
        assert_eq!(split_endpoint("nonsense"), None);
    }
}
