use serde::Deserialize;

/// A single captured request from the log.
///
/// Numeric fields are deliberately wider than the old `u8` versions: ids grow
/// past 255 and HTTP status codes go up to 5xx.
#[allow(dead_code)]
#[derive(Deserialize, Debug, Clone)]
pub struct Request {
    #[serde(default)]
    pub id: u64,
    #[serde(default)]
    pub host: String,
    #[serde(default)]
    pub method: String,
    #[serde(default)]
    pub path: String,
    #[serde(default)]
    pub length: u64,
    #[serde(default)]
    pub port: u16,
    #[serde(default)]
    pub raw: String,
    #[serde(default)]
    pub is_tls: bool,
    #[serde(default)]
    pub query: String,
    #[serde(default)]
    pub file_extension: Option<String>,
    #[serde(default)]
    pub source: String,
    #[serde(default)]
    pub response: Option<Response>,
    #[serde(default)]
    pub alteration: String,
    #[serde(default)]
    pub edited: bool,
    #[serde(default)]
    pub parent_id: Option<u64>,
    #[serde(default)]
    pub created_at: u64,
}

#[allow(dead_code)]
#[derive(Deserialize, Debug, Clone)]
pub struct Response {
    #[serde(default)]
    pub id: u64,
    #[serde(default)]
    pub status_code: u16,
    #[serde(default)]
    pub raw: String,
    #[serde(default)]
    pub length: u64,
    #[serde(default)]
    pub alteration: String,
    #[serde(default)]
    pub edited: bool,
    #[serde(default)]
    pub parent_id: Option<u64>,
    #[serde(default)]
    pub created_at: u64,
}

/// Build a full URL from the structured fields in the log.
///
/// `http://host[:port]/path[?query]`, with default ports (80/443) omitted.
pub fn build_url(req: &Request) -> String {
    let scheme = if req.is_tls { "https" } else { "http" };
    let default_port = if req.is_tls { 443 } else { 80 };

    let mut url = String::with_capacity(req.host.len() + req.path.len() + req.query.len() + 16);
    url.push_str(scheme);
    url.push_str("://");
    url.push_str(&req.host);

    if req.port != 0 && req.port != default_port {
        url.push(':');
        url.push_str(&req.port.to_string());
    }

    if req.path.is_empty() {
        url.push('/');
    } else if req.path.starts_with('/') {
        url.push_str(&req.path);
    } else {
        url.push('/');
        url.push_str(&req.path);
    }

    if !req.query.is_empty() && !req.path.contains('?') {
        url.push('?');
        url.push_str(&req.query);
    }

    url
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(host: &str, path: &str, query: &str, port: u16, is_tls: bool) -> Request {
        Request {
            id: 1,
            host: host.to_string(),
            method: "GET".to_string(),
            path: path.to_string(),
            length: 0,
            port,
            raw: String::new(),
            is_tls,
            query: query.to_string(),
            file_extension: None,
            source: String::new(),
            response: None,
            alteration: String::new(),
            edited: false,
            parent_id: None,
            created_at: 0,
        }
    }

    #[test]
    fn builds_https_url_and_omits_default_port() {
        let req = request("example.com", "/api", "a=1", 443, true);
        assert_eq!(build_url(&req), "https://example.com/api?a=1");
    }

    #[test]
    fn keeps_non_default_port() {
        let req = request("example.com", "/api", "", 8443, true);
        assert_eq!(build_url(&req), "https://example.com:8443/api");
    }

    #[test]
    fn builds_http_url_and_handles_empty_path() {
        let req = request("example.com", "", "", 80, false);
        assert_eq!(build_url(&req), "http://example.com/");
    }

    #[test]
    fn does_not_duplicate_query_separator() {
        let req = request("example.com", "/api?a=1", "b=2", 80, false);
        assert_eq!(build_url(&req), "http://example.com/api?a=1");
    }
}
