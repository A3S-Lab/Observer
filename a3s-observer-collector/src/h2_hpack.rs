//! Bounded HTTP/2 HEADERS HPACK decoder for Observer Collector.
//!
//! Decodes only `:method`, `:path`, `:status`, `content-type`, and `host`/`authority`.
//! Dynamic table is capped at 4 KiB. On decode failure the connection marks
//! `h2_hpack_desync` and callers continue the DATA body-only path.

use std::sync::OnceLock;

const MAX_DYNAMIC_TABLE_BYTES: usize = 4 * 1024;
const MAX_HEADER_VALUE_BYTES: usize = 2 * 1024;
const STATIC_TABLE_LEN: usize = 61;
const ENTRY_OVERHEAD: usize = 32;

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Http2HeaderBlock {
    pub method: Option<String>,
    pub path: Option<String>,
    pub status: Option<String>,
    pub content_type: Option<String>,
    pub authority: Option<String>,
    pub host: Option<String>,
}

#[derive(Clone, Debug)]
struct DynamicEntry {
    name: Vec<u8>,
    value: Vec<u8>,
}

impl DynamicEntry {
    fn size(&self) -> usize {
        self.name
            .len()
            .saturating_add(self.value.len())
            .saturating_add(ENTRY_OVERHEAD)
    }
}

#[derive(Debug)]
pub struct HpackDecoder {
    dynamic: Vec<DynamicEntry>,
    dynamic_size: usize,
    max_dynamic_size: usize,
    desync: bool,
}

impl Default for HpackDecoder {
    fn default() -> Self {
        Self {
            dynamic: Vec::new(),
            dynamic_size: 0,
            max_dynamic_size: MAX_DYNAMIC_TABLE_BYTES,
            desync: false,
        }
    }
}

impl HpackDecoder {
    #[cfg(test)]
    pub fn desynced(&self) -> bool {
        self.desync
    }
    pub fn mark_desync(&mut self) {
        self.desync = true;
        self.dynamic.clear();
        self.dynamic_size = 0;
        self.max_dynamic_size = MAX_DYNAMIC_TABLE_BYTES;
    }

    pub fn decode_block(&mut self, input: &[u8]) -> Result<Http2HeaderBlock, ()> {
        if self.desync {
            return Err(());
        }
        match self.decode_block_inner(input) {
            Ok(block) => Ok(block),
            Err(()) => {
                self.mark_desync();
                Err(())
            }
        }
    }

    fn decode_block_inner(&mut self, block: &[u8]) -> Result<Http2HeaderBlock, ()> {
        let mut selected = Http2HeaderBlock::default();
        let mut i = 0;
        while i < block.len() {
            let b = block[i];
            if b & 0x80 != 0 {
                let (index, consumed) = decode_int(block, i, 7).ok_or(())?;
                i = consumed;
                let (name, value) = self.lookup(index).ok_or(())?;
                retain_header(&mut selected, &name, &value);
            } else if b & 0xc0 == 0x40 {
                let (name, value, consumed) = self.decode_literal(block, i, 6).ok_or(())?;
                i = consumed;
                retain_header(&mut selected, &name, &value);
                self.push_dynamic(name, value);
            } else if b & 0xe0 == 0x20 {
                let (size, consumed) = decode_int(block, i, 5).ok_or(())?;
                i = consumed;
                self.max_dynamic_size = size.min(MAX_DYNAMIC_TABLE_BYTES);
                self.evict_to_size();
            } else if b & 0xf0 == 0x00 || b & 0xf0 == 0x10 {
                let (name, value, consumed) = self.decode_literal(block, i, 4).ok_or(())?;
                i = consumed;
                retain_header(&mut selected, &name, &value);
            } else {
                return Err(());
            }
        }
        Ok(selected)
    }

    fn decode_literal(
        &self,
        block: &[u8],
        start: usize,
        prefix_bits: u8,
    ) -> Option<(Vec<u8>, Vec<u8>, usize)> {
        let first = *block.get(start)?;
        let name_index_mask = (1u8 << prefix_bits) - 1;
        let (name, after_name) = if first & name_index_mask == 0 {
            let (name, consumed) = decode_string(block, start + 1)?;
            (name, consumed)
        } else {
            let (index, consumed) = decode_int(block, start, prefix_bits)?;
            let (name, _) = self.lookup(index)?;
            (name, consumed)
        };
        let (value, after_value) = decode_string(block, after_name)?;
        Some((name, value, after_value))
    }

    fn lookup(&self, index: usize) -> Option<(Vec<u8>, Vec<u8>)> {
        if index == 0 {
            return None;
        }
        if index <= STATIC_TABLE_LEN {
            let (name, value) = STATIC_TABLE[index - 1];
            return Some((name.as_bytes().to_vec(), value.as_bytes().to_vec()));
        }
        let dyn_index = index - STATIC_TABLE_LEN - 1;
        let entry = self.dynamic.get(dyn_index)?;
        Some((entry.name.clone(), entry.value.clone()))
    }

    fn push_dynamic(&mut self, name: Vec<u8>, value: Vec<u8>) {
        let entry = DynamicEntry { name, value };
        let size = entry.size();
        if size > self.max_dynamic_size {
            self.dynamic.clear();
            self.dynamic_size = 0;
            return;
        }
        self.dynamic.insert(0, entry);
        self.dynamic_size = self.dynamic_size.saturating_add(size);
        self.evict_to_size();
    }

    fn evict_to_size(&mut self) {
        while self.dynamic_size > self.max_dynamic_size {
            if let Some(old) = self.dynamic.pop() {
                self.dynamic_size = self.dynamic_size.saturating_sub(old.size());
            } else {
                self.dynamic_size = 0;
                break;
            }
        }
    }
}

fn retain_header(selected: &mut Http2HeaderBlock, name: &[u8], value: &[u8]) {
    let name = std::str::from_utf8(name).unwrap_or("").to_ascii_lowercase();
    let Ok(value) = std::str::from_utf8(value) else {
        return;
    };
    if value.len() > MAX_HEADER_VALUE_BYTES {
        return;
    }
    match name.as_str() {
        ":method" => selected.method = Some(value.to_string()),
        ":path" => selected.path = Some(value.to_string()),
        ":status" => selected.status = Some(value.to_string()),
        "content-type" => selected.content_type = Some(value.to_string()),
        ":authority" => selected.authority = Some(value.to_string()),
        "host" => selected.host = Some(value.to_string()),
        _ => {}
    }
}

fn decode_int(buf: &[u8], start: usize, prefix_bits: u8) -> Option<(usize, usize)> {
    let first = *buf.get(start)?;
    let mask = (1usize << prefix_bits) - 1;
    let mut value = (first as usize) & mask;
    let mut i = start + 1;
    if value < mask {
        return Some((value, i));
    }
    let mut m = 0u32;
    loop {
        let b = *buf.get(i)? as usize;
        i += 1;
        value = value.saturating_add((b & 0x7f) << m);
        if b & 0x80 == 0 {
            return Some((value, i));
        }
        m = m.saturating_add(7);
        if m > 28 {
            return None;
        }
    }
}

fn decode_string(buf: &[u8], start: usize) -> Option<(Vec<u8>, usize)> {
    let first = *buf.get(start)?;
    let huffman = first & 0x80 != 0;
    let (len, after_len) = decode_int(buf, start, 7)?;
    let end = after_len.checked_add(len)?;
    let raw = buf.get(after_len..end)?;
    let decoded = if huffman {
        huffman_decode(raw)?
    } else {
        raw.to_vec()
    };
    Some((decoded, end))
}

const HUFFMAN_CODES: [u32; 256] = [
    0x1ff8, 0x7fffd8, 0xfffffe2, 0xfffffe3, 0xfffffe4, 0xfffffe5, 0xfffffe6, 0xfffffe7, 0xfffffe8,
    0xffffea, 0x3ffffffc, 0xfffffe9, 0xfffffea, 0x3ffffffd, 0xfffffeb, 0xfffffec, 0xfffffed,
    0xfffffee, 0xfffffef, 0xffffff0, 0xffffff1, 0xffffff2, 0x3ffffffe, 0xffffff3, 0xffffff4,
    0xffffff5, 0xffffff6, 0xffffff7, 0xffffff8, 0xffffff9, 0xffffffa, 0xffffffb, 0x14, 0x3f8,
    0x3f9, 0xffa, 0x1ff9, 0x15, 0xf8, 0x7fa, 0x3fa, 0x3fb, 0xf9, 0x7fb, 0xfa, 0x16, 0x17, 0x18,
    0x0, 0x1, 0x2, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x5c, 0xfb, 0x7ffc, 0x20, 0xffb,
    0x3fc, 0x1ffa, 0x21, 0x5d, 0x5e, 0x5f, 0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68,
    0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f, 0x70, 0x71, 0x72, 0xfc, 0x73, 0xfd, 0x1ffb, 0x7fff0,
    0x1ffc, 0x3ffc, 0x22, 0x7ffd, 0x3, 0x23, 0x4, 0x24, 0x5, 0x25, 0x26, 0x27, 0x6, 0x74, 0x75,
    0x28, 0x29, 0x2a, 0x7, 0x2b, 0x76, 0x2c, 0x8, 0x9, 0x2d, 0x77, 0x78, 0x79, 0x7a, 0x7b, 0x7ffe,
    0x7fc, 0x3ffd, 0x1ffd, 0xffffffc, 0xfffe6, 0x3fffd2, 0xfffe7, 0xfffe8, 0x3fffd3, 0x3fffd4,
    0x3fffd5, 0x7fffd9, 0x3fffd6, 0x7fffda, 0x7fffdb, 0x7fffdc, 0x7fffdd, 0x7fffde, 0xffffeb,
    0x7fffdf, 0xffffec, 0xffffed, 0x3fffd7, 0x7fffe0, 0xffffee, 0x7fffe1, 0x7fffe2, 0x7fffe3,
    0x7fffe4, 0x1fffdc, 0x3fffd8, 0x7fffe5, 0x3fffd9, 0x7fffe6, 0x7fffe7, 0xffffef, 0x3fffda,
    0x1fffdd, 0xfffe9, 0x3fffdb, 0x3fffdc, 0x7fffe8, 0x7fffe9, 0x1fffde, 0x7fffea, 0x3fffdd,
    0x3fffde, 0xfffff0, 0x1fffdf, 0x3fffdf, 0x7fffeb, 0x7fffec, 0x1fffe0, 0x1fffe1, 0x3fffe0,
    0x1fffe2, 0x7fffed, 0x3fffe1, 0x7fffee, 0x7fffef, 0xfffea, 0x3fffe2, 0x3fffe3, 0x3fffe4,
    0x7ffff0, 0x3fffe5, 0x3fffe6, 0x7ffff1, 0x3ffffe0, 0x3ffffe1, 0xfffeb, 0x7fff1, 0x3fffe7,
    0x7ffff2, 0x3fffe8, 0x1ffffec, 0x3ffffe2, 0x3ffffe3, 0x3ffffe4, 0x7ffffde, 0x7ffffdf,
    0x3ffffe5, 0xfffff1, 0x1ffffed, 0x7fff2, 0x1fffe3, 0x3ffffe6, 0x7ffffe0, 0x7ffffe1, 0x3ffffe7,
    0x7ffffe2, 0xfffff2, 0x1fffe4, 0x1fffe5, 0x3ffffe8, 0x3ffffe9, 0xffffffd, 0x7ffffe3, 0x7ffffe4,
    0x7ffffe5, 0xfffec, 0xfffff3, 0xfffed, 0x1fffe6, 0x3fffe9, 0x1fffe7, 0x1fffe8, 0x7ffff3,
    0x3fffea, 0x3fffeb, 0x1ffffee, 0x1ffffef, 0xfffff4, 0xfffff5, 0x3ffffea, 0x7ffff4, 0x3ffffeb,
    0x7ffffe6, 0x3ffffec, 0x3ffffed, 0x7ffffe7, 0x7ffffe8, 0x7ffffe9, 0x7ffffea, 0x7ffffeb,
    0xffffffe, 0x7ffffec, 0x7ffffed, 0x7ffffee, 0x7ffffef, 0x7fffff0, 0x3ffffee,
];

const HUFFMAN_CODE_LEN: [u8; 256] = [
    13, 23, 28, 28, 28, 28, 28, 28, 28, 24, 30, 28, 28, 30, 28, 28, 28, 28, 28, 28, 28, 28, 30, 28,
    28, 28, 28, 28, 28, 28, 28, 28, 6, 10, 10, 12, 13, 6, 8, 11, 10, 10, 8, 11, 8, 6, 6, 6, 5, 5,
    5, 6, 6, 6, 6, 6, 6, 6, 7, 8, 15, 6, 12, 10, 13, 6, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
    7, 7, 7, 7, 7, 7, 7, 7, 8, 7, 8, 13, 19, 13, 14, 6, 15, 5, 6, 5, 6, 5, 6, 6, 6, 5, 7, 7, 6, 6,
    6, 5, 6, 7, 6, 5, 5, 6, 7, 7, 7, 7, 7, 15, 11, 14, 13, 28, 20, 22, 20, 20, 22, 22, 22, 23, 22,
    23, 23, 23, 23, 23, 24, 23, 24, 24, 22, 23, 24, 23, 23, 23, 23, 21, 22, 23, 22, 23, 23, 24, 22,
    21, 20, 22, 22, 23, 23, 21, 23, 22, 22, 24, 21, 22, 23, 23, 21, 21, 22, 21, 23, 22, 23, 23, 20,
    22, 22, 22, 23, 22, 22, 23, 26, 26, 20, 19, 22, 23, 22, 25, 26, 26, 26, 27, 27, 26, 24, 25, 19,
    21, 26, 27, 27, 26, 27, 24, 21, 21, 26, 26, 28, 27, 27, 27, 20, 24, 20, 21, 22, 21, 21, 23, 22,
    22, 25, 25, 24, 24, 26, 23, 26, 27, 26, 26, 27, 27, 27, 27, 27, 28, 27, 27, 27, 27, 27, 26,
];

#[derive(Clone, Copy)]
struct HuffmanNode {
    left: u16,
    right: u16,
    symbol: u16,
}

const HUFFMAN_NONE: u16 = u16::MAX;
const HUFFMAN_INTERNAL: u16 = u16::MAX - 1;

fn huffman_tree() -> &'static [HuffmanNode] {
    static TREE: OnceLock<Vec<HuffmanNode>> = OnceLock::new();
    TREE.get_or_init(|| {
        let mut nodes = vec![HuffmanNode {
            left: HUFFMAN_NONE,
            right: HUFFMAN_NONE,
            symbol: HUFFMAN_INTERNAL,
        }];
        for symbol in 0..256usize {
            let code = HUFFMAN_CODES[symbol];
            let nbits = HUFFMAN_CODE_LEN[symbol] as u32;
            let mut idx = 0usize;
            for shift in (0..nbits).rev() {
                let bit = ((code >> shift) & 1) as u8;
                let next = if bit == 0 {
                    nodes[idx].left
                } else {
                    nodes[idx].right
                };
                let child = if next == HUFFMAN_NONE {
                    let child = nodes.len() as u16;
                    nodes.push(HuffmanNode {
                        left: HUFFMAN_NONE,
                        right: HUFFMAN_NONE,
                        symbol: HUFFMAN_INTERNAL,
                    });
                    if bit == 0 {
                        nodes[idx].left = child;
                    } else {
                        nodes[idx].right = child;
                    }
                    child as usize
                } else {
                    next as usize
                };
                idx = child;
            }
            nodes[idx].symbol = symbol as u16;
        }
        nodes
    })
}

fn huffman_decode(input: &[u8]) -> Option<Vec<u8>> {
    let tree = huffman_tree();
    let mut out = Vec::new();
    let mut node = 0usize;
    let mut bits_since_symbol = 0u8;
    let mut saw_zero = false;
    for &byte in input {
        for shift in (0..8).rev() {
            let bit = (byte >> shift) & 1;
            let next = if bit == 0 {
                tree[node].left
            } else {
                tree[node].right
            };
            if next == HUFFMAN_NONE {
                return None;
            }
            node = next as usize;
            bits_since_symbol = bits_since_symbol.saturating_add(1);
            if bit == 0 {
                saw_zero = true;
            }
            if tree[node].symbol != HUFFMAN_INTERNAL {
                out.push(tree[node].symbol as u8);
                node = 0;
                bits_since_symbol = 0;
                saw_zero = false;
            }
        }
    }
    if node != 0 && (bits_since_symbol > 7 || saw_zero) {
        return None;
    }
    Some(out)
}

/// Static table (RFC 7541 Appendix A), 1-indexed externally.
const STATIC_TABLE: [(&str, &str); STATIC_TABLE_LEN] = [
    (":authority", ""),
    (":method", "GET"),
    (":method", "POST"),
    (":path", "/"),
    (":path", "/index.html"),
    (":scheme", "http"),
    (":scheme", "https"),
    (":status", "200"),
    (":status", "204"),
    (":status", "206"),
    (":status", "304"),
    (":status", "400"),
    (":status", "404"),
    (":status", "500"),
    ("accept-charset", ""),
    ("accept-encoding", "gzip, deflate"),
    ("accept-language", ""),
    ("accept-ranges", ""),
    ("accept", ""),
    ("access-control-allow-origin", ""),
    ("age", ""),
    ("allow", ""),
    ("authorization", ""),
    ("cache-control", ""),
    ("content-disposition", ""),
    ("content-encoding", ""),
    ("content-language", ""),
    ("content-length", ""),
    ("content-location", ""),
    ("content-range", ""),
    ("content-type", ""),
    ("cookie", ""),
    ("date", ""),
    ("etag", ""),
    ("expect", ""),
    ("expires", ""),
    ("from", ""),
    ("host", ""),
    ("if-match", ""),
    ("if-modified-since", ""),
    ("if-none-match", ""),
    ("if-range", ""),
    ("if-unmodified-since", ""),
    ("last-modified", ""),
    ("link", ""),
    ("location", ""),
    ("max-forwards", ""),
    ("proxy-authenticate", ""),
    ("proxy-authorization", ""),
    ("range", ""),
    ("referer", ""),
    ("refresh", ""),
    ("retry-after", ""),
    ("server", ""),
    ("set-cookie", ""),
    ("strict-transport-security", ""),
    ("transfer-encoding", ""),
    ("user-agent", ""),
    ("vary", ""),
    ("via", ""),
    ("www-authenticate", ""),
];

#[cfg(test)]
fn encode_int(value: usize, prefix_bits: u8, prefix_mask: u8) -> Vec<u8> {
    let max = (1usize << prefix_bits) - 1;
    if value < max {
        return vec![prefix_mask | (value as u8)];
    }
    let mut out = vec![prefix_mask | (max as u8)];
    let mut v = value - max;
    while v >= 128 {
        out.push(((v as u8) & 0x7f) | 0x80);
        v >>= 7;
    }
    out.push(v as u8);
    out
}

#[cfg(test)]
fn encode_string(value: &[u8]) -> Vec<u8> {
    let mut out = encode_int(value.len(), 7, 0x00);
    out.extend_from_slice(value);
    out
}

#[cfg(test)]
fn hpack_encode_indexed(index: usize) -> Vec<u8> {
    encode_int(index, 7, 0x80)
}

#[cfg(test)]
fn hpack_encode_literal_without_indexing(name_index: usize, value: &[u8]) -> Vec<u8> {
    let mut out = encode_int(name_index, 4, 0x00);
    out.extend(encode_string(value));
    out
}

#[cfg(test)]
fn hpack_encode_literal_name_value(name: &[u8], value: &[u8]) -> Vec<u8> {
    let mut out = vec![0x00];
    out.extend(encode_string(name));
    out.extend(encode_string(value));
    out
}

#[cfg(test)]
fn static_name_index(name: &str) -> Option<usize> {
    STATIC_TABLE
        .iter()
        .enumerate()
        .find(|(_, (n, _))| n.eq_ignore_ascii_case(name))
        .map(|(idx, _)| idx + 1)
}

#[cfg(test)]
fn static_full_index(name: &str, value: &str) -> Option<usize> {
    STATIC_TABLE
        .iter()
        .enumerate()
        .find(|(_, (n, v))| n.eq_ignore_ascii_case(name) && *v == value)
        .map(|(idx, _)| idx + 1)
}

#[cfg(test)]
/// Encode a literal header list for fixtures (not on the capture hot path).
pub fn encode_headers(headers: &[(&str, &str)]) -> Vec<u8> {
    let mut out = Vec::new();
    for &(name, value) in headers {
        if let Some(index) = static_full_index(name, value) {
            out.extend(hpack_encode_indexed(index));
            continue;
        }
        if let Some(index) = static_name_index(name) {
            out.extend(hpack_encode_literal_without_indexing(
                index,
                value.as_bytes(),
            ));
            continue;
        }
        out.extend(hpack_encode_literal_name_value(
            name.as_bytes(),
            value.as_bytes(),
        ));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hpack_indexed_method_post() {
        let mut decoder = HpackDecoder::default();
        let block = decoder.decode_block(&[0x83]).expect("indexed POST");
        assert_eq!(block.method.as_deref(), Some("POST"));
    }

    #[test]
    fn hpack_literal_path() {
        let mut decoder = HpackDecoder::default();
        let bytes = hpack_encode_literal_without_indexing(4, b"/v1/responses");
        let block = decoder.decode_block(&bytes).expect("path");
        assert_eq!(block.path.as_deref(), Some("/v1/responses"));
    }

    #[test]
    fn hpack_indexed_status_200() {
        let mut decoder = HpackDecoder::default();
        let block = decoder.decode_block(&[0x88]).expect("indexed 200");
        assert_eq!(block.status.as_deref(), Some("200"));
    }

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
        assert!(decoder.decode_block(&[0x83]).is_err());
    }
}
