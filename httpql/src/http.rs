use base64::Engine;
use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE};
use memchr::memmem;

/// A decoded HTTP request or response, split into its header block and body.
pub struct HttpMessage {
    raw: Vec<u8>,
    header_start: usize,
    header_end: usize,
    body_start: usize,
}

impl HttpMessage {
    pub fn parse(raw: Vec<u8>) -> Self {
        let (header_end, body_start) = match find_header_separator(&raw) {
            Some((position, separator_len)) => (position, position + separator_len),
            None => (raw.len(), raw.len()),
        };

        // Skip the request/status line so `headers()` contains only headers.
        // When there is no newline (or no headers at all), headers are empty.
        let header_start = match raw[..header_end].iter().position(|&byte| byte == b'\n') {
            Some(position) => (position + 1).min(header_end),
            None => header_end,
        };

        Self {
            raw,
            header_start,
            header_end,
            body_start,
        }
    }

    pub fn raw(&self) -> &[u8] {
        &self.raw
    }

    pub fn headers(&self) -> &[u8] {
        let mut end = self.header_end;
        while end > self.header_start && matches!(self.raw[end - 1], b'\r' | b'\n') {
            end -= 1;
        }
        &self.raw[self.header_start..end]
    }

    pub fn body(&self) -> &[u8] {
        &self.raw[self.body_start..]
    }
}

fn find_header_separator(bytes: &[u8]) -> Option<(usize, usize)> {
    let crlf = memmem::find(bytes, b"\r\n\r\n").map(|position| (position, 4));
    let lf = memmem::find(bytes, b"\n\n").map(|position| (position, 2));

    match (crlf, lf) {
        (Some(crlf), Some(lf)) => Some(if crlf.0 <= lf.0 { crlf } else { lf }),
        (Some(crlf), None) => Some(crlf),
        (None, Some(lf)) => Some(lf),
        (None, None) => None,
    }
}

/// Decode the base64 `raw` field from the log.
pub fn decode_base64(raw: &str) -> Result<Vec<u8>, base64::DecodeError> {
    if raw.is_empty() {
        return Ok(Vec::new());
    }

    STANDARD
        .decode(raw)
        .or_else(|_| STANDARD_NO_PAD.decode(raw))
        .or_else(|_| URL_SAFE.decode(raw))
}

/// Byte-safe substring search so binary bodies work without UTF-8 conversion.
pub fn contains(haystack: &[u8], needle: &str) -> bool {
    if needle.is_empty() {
        return true;
    }
    memmem::find(haystack, needle.as_bytes()).is_some()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splits_crlf_http_message() {
        let message =
            HttpMessage::parse(b"GET / HTTP/1.1\r\nHost: x\r\nX-Test: yes\r\n\r\nhello".to_vec());

        assert_eq!(message.headers(), b"Host: x\r\nX-Test: yes".as_slice());
        assert_eq!(message.body(), b"hello".as_slice());
        assert_eq!(
            message.raw(),
            b"GET / HTTP/1.1\r\nHost: x\r\nX-Test: yes\r\n\r\nhello".as_slice()
        );
    }

    #[test]
    fn splits_lf_http_message() {
        let message =
            HttpMessage::parse(b"HTTP/1.1 200 OK\nContent-Type: text/plain\n\nbody".to_vec());

        assert_eq!(message.headers(), b"Content-Type: text/plain".as_slice());
        assert_eq!(message.body(), b"body".as_slice());
    }

    #[test]
    fn handles_message_without_body() {
        let message = HttpMessage::parse(b"HTTP/1.1 204 No Content\r\nDate: now\r\n".to_vec());

        assert_eq!(message.headers(), b"Date: now".as_slice());
        assert_eq!(message.body(), b"".as_slice());
    }

    #[test]
    fn handles_message_without_headers() {
        let message = HttpMessage::parse(b"GET / HTTP/1.1\r\n\r\nbody".to_vec());

        assert_eq!(message.headers(), b"".as_slice());
        assert_eq!(message.body(), b"body".as_slice());
    }

    #[test]
    fn uses_earliest_header_separator() {
        let message = HttpMessage::parse(
            b"HTTP/1.1 200 OK\nContent-Type: text/plain\n\nbody\r\n\r\nmore".to_vec(),
        );

        assert_eq!(message.headers(), b"Content-Type: text/plain".as_slice());
        assert_eq!(message.body(), b"body\r\n\r\nmore".as_slice());
    }

    #[test]
    fn decodes_standard_and_unpadded_base64() {
        assert_eq!(decode_base64("aGVsbG8=").unwrap(), b"hello");
        assert_eq!(decode_base64("aGVsbG8").unwrap(), b"hello");
    }

    #[test]
    fn searches_binary_safe() {
        assert!(contains(b"abc\x00def", "c\x00d"));
        assert!(!contains(b"abc", "xyz"));
        assert!(contains(b"abc", ""));
    }
}
