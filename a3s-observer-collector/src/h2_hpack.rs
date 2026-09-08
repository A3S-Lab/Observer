//! Bounded HTTP/2 HEADERS HPACK decoder for Observer Collector.
//!
//! Decodes only `:method`, `:path`, `:status`, `content-type`, and `host`/`authority`.
//! Dynamic table is capped at 4 KiB. On decode failure the connection marks
//! `h2_hpack_desync` and callers continue the DATA body-only path.

use hpack::Decoder;

const MAX_DYNAMIC_TABLE_BYTES: usize = 4 * 1024;
const MAX_HEADER_VALUE_BYTES: usize = 2 * 1024;

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Http2HeaderBlock {
    pub method: Option<String>,
    pub path: Option<String>,
    pub status: Option<String>,
    pub content_type: Option<String>,
    pub authority: Option<String>,
    pub host: Option<String>,
}

pub struct HpackDecoder {
    inner: Decoder<'static>,
    desync: bool,
}

impl std::fmt::Debug for HpackDecoder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HpackDecoder")
            .field("desync", &self.desync)
            .finish()
    }
}

impl Default for HpackDecoder {
    fn default() -> Self {
        let mut inner = Decoder::new();
        inner.set_max_table_size(MAX_DYNAMIC_TABLE_BYTES);
        Self {
            inner,
            desync: false,
        }
    }
}

impl HpackDecoder {
    pub fn desynced(&self) -> bool {
        self.desync
    }

    pub fn mark_desync(&mut self) {
        self.desync = true;
        self.inner = Decoder::new();
        self.inner.set_max_table_size(MAX_DYNAMIC_TABLE_BYTES);
    }

    pub fn decode_block(&mut self, input: &[u8]) -> Result<Http2HeaderBlock, ()> {
        if self.desync {
            return Err(());
        }
        let decoded = match self.inner.decode(input) {
            Ok(value) => value,
            Err(_) => {
                self.mark_desync();
                return Err(());
            }
        };
        let mut out = Http2HeaderBlock::default();
        for (name, value) in decoded {
            let Ok(name) = std::str::from_utf8(&name) else {
                continue;
            };
            let Ok(value) = std::str::from_utf8(&value) else {
                continue;
            };
            if value.len() > MAX_HEADER_VALUE_BYTES {
                continue;
            }
            match name {
                ":method" => out.method = Some(value.to_string()),
                ":path" => out.path = Some(value.to_string()),
                ":status" => out.status = Some(value.to_string()),
                "content-type" => out.content_type = Some(value.to_string()),
                ":authority" => out.authority = Some(value.to_string()),
                "host" => out.host = Some(value.to_string()),
                _ => {}
            }
        }
        Ok(out)
    }
}

/// Encode a literal header list with a throwaway Encoder for unit/fixtures (not on hot path).
#[cfg(test)]
pub fn encode_headers(headers: &[(&str, &str)]) -> Vec<u8> {
    use hpack::Encoder;
    let mut encoder = Encoder::new();
    let owned: Vec<(Vec<u8>, Vec<u8>)> = headers
        .iter()
        .map(|(n, v)| (n.as_bytes().to_vec(), v.as_bytes().to_vec()))
        .collect();
    let refs: Vec<(&[u8], &[u8])> = owned.iter().map(|(n, v)| (n.as_slice(), v.as_slice())).collect();
    encoder.encode(refs)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_method_path_status() {
        let bytes = encode_headers(&[
            (":method", "POST"),
            (":path", "/v1/responses"),
            (":status", "200"),
            ("content-type", "application/json"),
            (":authority", "api.openai.com"),
        ]);
        let mut decoder = HpackDecoder::default();
        let block = decoder.decode_block(&bytes).expect("decode");
        assert_eq!(block.method.as_deref(), Some("POST"));
        assert_eq!(block.path.as_deref(), Some("/v1/responses"));
        assert_eq!(block.status.as_deref(), Some("200"));
        assert_eq!(block.content_type.as_deref(), Some("application/json"));
        assert_eq!(block.authority.as_deref(), Some("api.openai.com"));
    }

    #[test]
    fn desync_on_garbage() {
        let mut decoder = HpackDecoder::default();
        assert!(decoder.decode_block(&[0xff, 0xff, 0xff, 0xff]).is_err());
        assert!(decoder.desynced());
    }
}
