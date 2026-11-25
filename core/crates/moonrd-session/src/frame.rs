//! Framing for reliable streams: each message is a varint length prefix followed by
//! one encoded `Envelope` (protobuf's standard length-delimited form).

use moonrd_proto::Envelope;
use prost::Message;

/// Largest accepted frame body. A 4K keyframe fits comfortably; anything larger is
/// treated as a protocol error rather than buffered.
pub const MAX_FRAME: usize = 8 << 20;

/// Errors while decoding a stream of frames.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum FrameError {
    #[error("frame of {0} bytes exceeds the {MAX_FRAME}-byte limit")]
    TooLarge(usize),
    #[error("malformed length prefix")]
    BadLength,
    #[error("malformed message: {0}")]
    Decode(String),
}

/// Encodes one envelope with its length prefix.
pub fn encode(msg: &Envelope) -> Vec<u8> {
    msg.encode_length_delimited_to_vec()
}

/// Incremental decoder: feed it bytes as they arrive and pull complete envelopes.
#[derive(Default)]
pub struct Decoder {
    buf: Vec<u8>,
}

impl Decoder {
    pub fn new() -> Self {
        Self::default()
    }

    /// Appends received bytes.
    pub fn push(&mut self, bytes: &[u8]) {
        self.buf.extend_from_slice(bytes);
    }

    /// Returns the next complete envelope, `Ok(None)` if more bytes are needed.
    /// After an error the stream must be closed: framing cannot resynchronise.
    pub fn next_frame(&mut self) -> Result<Option<Envelope>, FrameError> {
        let Some((len, prefix)) = read_varint(&self.buf)? else {
            return Ok(None);
        };
        let len = usize::try_from(len).map_err(|_| FrameError::TooLarge(usize::MAX))?;
        if len > MAX_FRAME {
            return Err(FrameError::TooLarge(len));
        }
        if self.buf.len() < prefix + len {
            return Ok(None);
        }
        let msg = Envelope::decode(&self.buf[prefix..prefix + len]).map_err(|e| FrameError::Decode(e.to_string()))?;
        self.buf.drain(..prefix + len);
        Ok(Some(msg))
    }

    /// Bytes buffered but not yet decoded.
    pub fn pending(&self) -> usize {
        self.buf.len()
    }
}

/// Reads a protobuf varint; `Ok(None)` if the buffer ends inside it.
fn read_varint(buf: &[u8]) -> Result<Option<(u64, usize)>, FrameError> {
    let mut value: u64 = 0;
    for (i, &b) in buf.iter().enumerate().take(10) {
        value |= u64::from(b & 0x7f) << (7 * i);
        if b & 0x80 == 0 {
            return Ok(Some((value, i + 1)));
        }
    }
    if buf.len() >= 10 { Err(FrameError::BadLength) } else { Ok(None) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use moonrd_proto::{envelope::Msg, Ping, VideoFrame};

    fn ping(n: u64) -> Envelope {
        Envelope { msg: Some(Msg::Ping(Ping { nonce: n, sent_time_us: n * 10 })) }
    }

    #[test]
    fn round_trip_byte_by_byte() {
        let mut wire = Vec::new();
        for n in 0..50 {
            wire.extend(encode(&ping(n)));
        }
        let mut d = Decoder::new();
        let mut got = Vec::new();
        for b in wire {
            d.push(&[b]);
            while let Some(m) = d.next_frame().unwrap() {
                got.push(m);
            }
        }
        assert_eq!(got, (0..50).map(ping).collect::<Vec<_>>());
        assert_eq!(d.pending(), 0);
    }

    #[test]
    fn large_frame_within_limit() {
        let big = Envelope {
            msg: Some(Msg::VideoFrame(VideoFrame { sequence: 1, capture_time_us: 2, keyframe: true, data: vec![7; 2 << 20] })),
        };
        let mut d = Decoder::new();
        d.push(&encode(&big));
        assert_eq!(d.next_frame().unwrap(), Some(big));
    }

    #[test]
    fn rejects_oversized_length_before_buffering() {
        let mut d = Decoder::new();
        // varint for MAX_FRAME + 1 with no body: must fail immediately.
        let mut prefix = Vec::new();
        prost::encoding::encode_varint((MAX_FRAME + 1) as u64, &mut prefix);
        d.push(&prefix);
        assert_eq!(d.next_frame(), Err(FrameError::TooLarge(MAX_FRAME + 1)));
    }

    #[test]
    fn rejects_overlong_varint_and_garbage() {
        let mut d = Decoder::new();
        d.push(&[0xff; 10]);
        assert_eq!(d.next_frame(), Err(FrameError::BadLength));

        let mut d = Decoder::new();
        d.push(&[3, 0xff, 0xff, 0xff]); // length 3, invalid protobuf body
        assert!(matches!(d.next_frame(), Err(FrameError::Decode(_))));
    }
}
