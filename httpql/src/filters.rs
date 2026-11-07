use crate::http::{self, HttpMessage};
use crate::model::Request;

/// All filters are ANDed together. `contains`/`ncontains` are case-sensitive.
#[derive(Default, Debug)]
pub struct Filters {
    pub req_url_contains: Option<String>,
    pub req_url_ncontains: Option<String>,
    pub req_method_contains: Option<String>,
    pub req_method_ncontains: Option<String>,
    pub req_headers_contains: Option<String>,
    pub req_headers_ncontains: Option<String>,
    pub req_body_contains: Option<String>,
    pub req_body_ncontains: Option<String>,
    pub req_raw_contains: Option<String>,
    pub req_raw_ncontains: Option<String>,
    pub resp_headers_contains: Option<String>,
    pub resp_headers_ncontains: Option<String>,
    pub resp_body_contains: Option<String>,
    pub resp_body_ncontains: Option<String>,
    pub resp_raw_contains: Option<String>,
    pub resp_raw_ncontains: Option<String>,
}

impl Filters {
    pub fn needs_request_raw(&self) -> bool {
        self.req_headers_contains.is_some()
            || self.req_headers_ncontains.is_some()
            || self.req_body_contains.is_some()
            || self.req_body_ncontains.is_some()
            || self.req_raw_contains.is_some()
            || self.req_raw_ncontains.is_some()
    }

    pub fn needs_response_raw(&self) -> bool {
        self.resp_headers_contains.is_some()
            || self.resp_headers_ncontains.is_some()
            || self.resp_body_contains.is_some()
            || self.resp_body_ncontains.is_some()
            || self.resp_raw_contains.is_some()
            || self.resp_raw_ncontains.is_some()
    }

    pub fn matches(&self, request: &Request, url: &str) -> bool {
        if !match_str(url, &self.req_url_contains, &self.req_url_ncontains) {
            return false;
        }

        if !match_str(
            &request.method,
            &self.req_method_contains,
            &self.req_method_ncontains,
        ) {
            return false;
        }

        if self.needs_request_raw() {
            match http::decode_base64(&request.raw) {
                Ok(bytes) => {
                    let message = HttpMessage::parse(bytes);
                    if !match_bytes(
                        message.headers(),
                        &self.req_headers_contains,
                        &self.req_headers_ncontains,
                    ) {
                        return false;
                    }
                    if !match_bytes(
                        message.body(),
                        &self.req_body_contains,
                        &self.req_body_ncontains,
                    ) {
                        return false;
                    }
                    if !match_bytes(
                        message.raw(),
                        &self.req_raw_contains,
                        &self.req_raw_ncontains,
                    ) {
                        return false;
                    }
                }
                Err(_) => {
                    if self.req_headers_contains.is_some()
                        || self.req_body_contains.is_some()
                        || self.req_raw_contains.is_some()
                    {
                        return false;
                    }
                }
            }
        }

        if self.needs_response_raw() {
            match &request.response {
                Some(response) => match http::decode_base64(&response.raw) {
                    Ok(bytes) => {
                        let message = HttpMessage::parse(bytes);
                        if !match_bytes(
                            message.headers(),
                            &self.resp_headers_contains,
                            &self.resp_headers_ncontains,
                        ) {
                            return false;
                        }
                        if !match_bytes(
                            message.body(),
                            &self.resp_body_contains,
                            &self.resp_body_ncontains,
                        ) {
                            return false;
                        }
                        if !match_bytes(
                            message.raw(),
                            &self.resp_raw_contains,
                            &self.resp_raw_ncontains,
                        ) {
                            return false;
                        }
                    }
                    Err(_) => {
                        if self.resp_headers_contains.is_some()
                            || self.resp_body_contains.is_some()
                            || self.resp_raw_contains.is_some()
                        {
                            return false;
                        }
                    }
                },
                None => {
                    // A missing response cannot contain anything, but it does
                    // satisfy `ncontains` filters.
                    if self.resp_headers_contains.is_some()
                        || self.resp_body_contains.is_some()
                        || self.resp_raw_contains.is_some()
                    {
                        return false;
                    }
                }
            }
        }

        true
    }
}

fn match_str(value: &str, contains: &Option<String>, ncontains: &Option<String>) -> bool {
    if let Some(needle) = contains
        && !value.contains(needle.as_str())
    {
        return false;
    }
    if let Some(needle) = ncontains
        && value.contains(needle.as_str())
    {
        return false;
    }
    true
}

fn match_bytes(value: &[u8], contains: &Option<String>, ncontains: &Option<String>) -> bool {
    if let Some(needle) = contains
        && !http::contains(value, needle)
    {
        return false;
    }
    if let Some(needle) = ncontains
        && http::contains(value, needle)
    {
        return false;
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Response;
    use base64::Engine;
    use base64::engine::general_purpose::STANDARD;

    fn request() -> Request {
        Request {
            id: 1,
            host: "example.com".to_string(),
            method: "POST".to_string(),
            path: "/api".to_string(),
            length: 0,
            port: 443,
            raw: STANDARD.encode(
                b"POST /api HTTP/1.1\r\nHost: example.com\r\nX-Test: yes\r\n\r\nhello body",
            ),
            is_tls: true,
            query: "a=1".to_string(),
            file_extension: None,
            source: String::new(),
            response: Some(Response {
                id: 1,
                status_code: 200,
                raw: STANDARD
                    .encode(b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nresponse body"),
                length: 0,
                alteration: String::new(),
                edited: false,
                parent_id: None,
                created_at: 0,
            }),
            alteration: String::new(),
            edited: false,
            parent_id: None,
            created_at: 0,
        }
    }

    fn filters() -> Filters {
        Filters::default()
    }

    #[test]
    fn matches_url_and_method() {
        let req = request();
        let url = crate::model::build_url(&req);

        let mut f = filters();
        f.req_url_contains = Some("https://example.com/api?a=1".to_string());
        assert!(f.matches(&req, &url));

        f.req_method_contains = Some("POST".to_string());
        assert!(f.matches(&req, &url));

        f.req_method_ncontains = Some("POST".to_string());
        assert!(!f.matches(&req, &url));
    }

    #[test]
    fn matches_request_headers_body_and_raw() {
        let req = request();
        let url = crate::model::build_url(&req);

        let mut f = filters();
        f.req_headers_contains = Some("X-Test: yes".to_string());
        assert!(f.matches(&req, &url));

        f.req_body_contains = Some("hello".to_string());
        assert!(f.matches(&req, &url));

        f.req_raw_contains = Some("POST /api HTTP/1.1".to_string());
        assert!(f.matches(&req, &url));

        f.req_body_ncontains = Some("hello".to_string());
        assert!(!f.matches(&req, &url));
    }

    #[test]
    fn matches_response_headers_body_and_raw() {
        let req = request();
        let url = crate::model::build_url(&req);

        let mut f = filters();
        f.resp_headers_contains = Some("Content-Type".to_string());
        assert!(f.matches(&req, &url));

        f.resp_body_contains = Some("response body".to_string());
        assert!(f.matches(&req, &url));

        f.resp_raw_contains = Some("200 OK".to_string());
        assert!(f.matches(&req, &url));
    }

    #[test]
    fn null_response_fails_contains_but_passes_ncontains() {
        let mut req = request();
        req.response = None;
        let url = crate::model::build_url(&req);

        let mut f = filters();
        f.resp_body_contains = Some("anything".to_string());
        assert!(!f.matches(&req, &url));

        f.resp_body_contains = None;
        f.resp_body_ncontains = Some("anything".to_string());
        assert!(f.matches(&req, &url));
    }

    #[test]
    fn all_filters_must_match() {
        let req = request();
        let url = crate::model::build_url(&req);

        let mut f = filters();
        f.req_url_contains = Some("example.com".to_string());
        f.req_method_contains = Some("GET".to_string());
        assert!(!f.matches(&req, &url));
    }
}
