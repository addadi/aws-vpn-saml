use std::path::Path;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::Command;
use tokio::time::{timeout, Duration};
use tracing::{debug, info};

pub struct ChallengeData {
    pub saml_url: String,
    pub state_id: String,
}

pub struct RemoteInfo {
    pub ip: String,
}

pub async fn resolve_remote(ovpn_conf: &Path) -> Result<RemoteInfo, String> {
    let content = std::fs::read_to_string(ovpn_conf)
        .map_err(|e| format!("failed to read ovpn config: {e}"))?;

    let hostname = content
        .lines()
        .find_map(|line| {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.get(0) == Some(&"remote") {
                parts.get(1).map(|s| s.to_string())
            } else {
                None
            }
        })
        .ok_or_else(|| "no 'remote' directive found in ovpn config".to_string())?;

    let random_hex = {
        use std::fmt::Write;
        let bytes: [u8; 12] = rand_fill();
        let mut s = String::with_capacity(24);
        for b in &bytes {
            write!(s, "{b:02x}").unwrap();
        }
        s
    };

    let lookup_host = format!("{random_hex}.{hostname}");

    let addrs = tokio::net::lookup_host(format!("{lookup_host}:443"))
        .await
        .map_err(|e| format!("DNS lookup failed for {lookup_host}: {e}"))?;

    let ip = addrs
        .into_iter()
        .next()
        .map(|a| a.ip().to_string())
        .ok_or_else(|| "no IP addresses found".to_string())?;

    info!(ip = %ip, "resolved remote IP");
    Ok(RemoteInfo { ip })
}

fn rand_fill() -> [u8; 12] {
    let mut buf = [0u8; 12];
    use std::io::Read;
    std::io::BufReader::new(std::fs::File::open("/dev/urandom").unwrap())
        .read_exact(&mut buf)
        .unwrap();
    buf
}

pub async fn get_challenge(
    ovpn_bin: &Path,
    ovpn_conf: &Path,
    remote_ip: &str,
    timeout_secs: u64,
) -> Result<ChallengeData, String> {
    let password = "ACS::35001";
    let username = "N/A";

    let child = Command::new("bash")
        .arg("-c")
        .arg(format!(
            "{} --config {} --remote {} 443 --auth-user-pass <( printf '%s\n%s\n' '{}' '{}' )",
            ovpn_bin.display(),
            ovpn_conf.display(),
            remote_ip,
            username,
            password
        ))
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()
        .map_err(|e| format!("failed to spawn openvpn: {e}"))?;

    let stdout = child.stdout.expect("stdout captured");
    let reader = BufReader::new(stdout);
    let mut lines = reader.lines();

    let deadline = Duration::from_secs(timeout_secs);

    let result = timeout(deadline, async {
        while let Ok(Some(line)) = lines.next_line().await {
            debug!(line = %line, "openvpn output");

            if let Some(data) = parse_crv1_line(&line) {
                return Ok(data);
            }
        }
        Err("no CRV1 challenge found in OpenVPN output".to_string())
    })
    .await;

    match result {
        Ok(Ok(data)) => {
            info!(
                url_len = data.saml_url.len(),
                state_id = %data.state_id,
                "found CRV1 challenge"
            );
            Ok(data)
        }
        Ok(Err(e)) => Err(e),
        Err(_) => {
            Err(format!(
                "timeout waiting for CRV1 challenge ({timeout_secs}s)"
            ))
        }
    }
}

fn parse_crv1_line(line: &str) -> Option<ChallengeData> {
    if !line.contains("CRV1:") {
        return None;
    }

    let url = extract_url(line)?;
    let state_id = extract_state_id(line, &url)?;

    if url.is_empty() || state_id.is_empty() {
        return None;
    }

    Some(ChallengeData {
        saml_url: url,
        state_id,
    })
}

fn extract_state_id(s: &str, _url: &str) -> Option<String> {
    let instance_idx = s.find("instance-")?;
    let url_idx = s.rfind("https://")?;

    if url_idx <= instance_idx {
        return None;
    }

    let before_url = &s[instance_idx..url_idx];

    // before_url looks like: "instance-2/ID/UUID:b'Ti9B':" or "instance-2/ID/UUID:base64:"
    // The state_id is the first colon-delimited field
    let colon_pos = before_url.find(':')?;

    let state_id = &before_url[..colon_pos];

    if state_id.is_empty() {
        return None;
    }

    Some(state_id.to_string())
}

fn extract_url(s: &str) -> Option<String> {
    let idx = s.find("https://")?;
    Some(s[idx..].trim_end_matches('\n').to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_crv1_single_line() {
        let line = "AUTH_FAILED,CRV1:R:instance-2/1234/abcd:base64:https://portal.sso.us-east-1.amazonaws.com/saml/assertion/NTA5?SAMLRequest=abc";
        let data = parse_crv1_line(line).unwrap();
        assert!(data.saml_url.starts_with("https://"));
        assert_eq!(data.state_id, "instance-2/1234/abcd");
    }

    #[test]
    fn test_parse_crv1_split_line() {
        let line = "WARNING: Received unknown control message: _FAILED,CRV1:R:instance-1/7637815123092575839/e23043e9:base64:https://portal.sso.us-east-1.amazonaws.com/saml/assertion/NTA5?SAMLRequest=xyz";
        let data = parse_crv1_line(line).unwrap();
        assert!(data.saml_url.starts_with("https://"));
        assert_eq!(data.state_id, "instance-1/7637815123092575839/e23043e9");
    }

    #[test]
    fn test_parse_crv1_no_crv1() {
        let line = "2026-05-09 SENT CONTROL [*.infra.vhive.ai]: 'PUSH_REQUEST' (status=1)";
        assert!(parse_crv1_line(line).is_none());
    }

    #[test]
    fn test_parse_crv1_full_real_output() {
        let line = "2026-05-09 12:01:44 WARNING: Received unknown control message: _FAILED,CRV1:R:instance-2/7637814664337430111/b9ebe713-6b13-45d0-80b7-6a60cfc361b4:b'Ti9B':https://portal.sso.us-east-1.amazonaws.com/saml/assertion/NTA5Mzg5MTgxMTExX2lucy1mMzZiOGY4YTU1OGJlNjgy?SAMLRequest=fZLLbtswEEX3";
        let data = parse_crv1_line(line).unwrap();
        assert!(data.saml_url.starts_with("https://portal.sso"));
        assert_eq!(data.state_id, "instance-2/7637814664337430111/b9ebe713-6b13-45d0-80b7-6a60cfc361b4");
    }

    #[test]
    fn test_parse_crv1_auth_failed_prefix() {
        let line = "AUTH_FAILED,CRV1:R:instance-3/999/xyz:abc:https://example.com/saml";
        let data = parse_crv1_line(line).unwrap();
        assert!(data.saml_url.starts_with("https://example.com"));
        assert_eq!(data.state_id, "instance-3/999/xyz");
    }
}