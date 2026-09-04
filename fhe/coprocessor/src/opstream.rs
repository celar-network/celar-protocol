//! Decoding §3's event envelope.
//!
//! Layout, from the frozen table:
//!
//! ```text
//! version(1) ‖ opcode(1) ‖ resultType(1) ‖ operandCount(1) ‖
//! operands(32×n) ‖ resultHandle(32) ‖ hcuCost(4) ‖ auxLen(2) ‖ aux
//! ```
//!
//! Big-endian for the two numeric fields.

/// §3: `topics[0]` is `keccak256` of this. Kept as the preimage rather than the
/// hash so a reader can recompute it and so the two implementations of this
/// stream agree on a string rather than on a constant one of them typed.
pub const STREAM_TOPIC_PREIMAGE: &str = "celar.opstream.v1";

/// The only envelope version this consumer understands.
pub const ENVELOPE_VERSION: u8 = 0x01;

#[derive(Debug, PartialEq, Eq)]
pub struct StreamEvent {
    pub version: u8,
    pub opcode: u8,
    /// Left UNINTERPRETED on purpose.
    ///
    /// §3 codes this `0 = ebool, 3 = euint8 … 6 = euint64`. A draft amendment
    /// would add `0xFF = UNKNOWN` for admission, whose ABI carries no width —
    /// but that amendment is not declared. Interpreting the byte now means
    /// either encoding undeclared semantics or rejecting a value about to
    /// become legal. Carrying it raw does neither; interpretation is a
    /// separate step, gated on the declaration.
    pub result_type: u8,
    pub operands: Vec<[u8; 32]>,
    pub result_handle: [u8; 32],
    pub hcu_cost: u32,
    pub aux: Vec<u8>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum DecodeError {
    /// §3: "A consumer seeing an unknown version MUST halt consumption of that
    /// stream (fail-safe)". So this is not a skip and not a warning.
    UnknownVersion(u8),
    /// §3 caps operandCount at 3 (`select` is the widest op).
    TooManyOperands(u8),
    /// Ran out of bytes where the layout requires them. Carries what it was
    /// reading, because "unexpected EOF" on a packed struct is unactionable.
    Truncated(&'static str),
    /// `auxLen` disagrees with the bytes that follow it.
    AuxLengthMismatch { declared: usize, present: usize },
    /// Bytes remain after a complete event. One log is one op, so this means
    /// the reader and the writer disagree about the layout.
    TrailingBytes(usize),
}

impl core::fmt::Display for DecodeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::UnknownVersion(v) => write!(
                f,
                "op-stream: envelope version {v:#04x} is not {ENVELOPE_VERSION:#04x}; \
                 halting consumption rather than guessing at the layout"
            ),
            Self::TooManyOperands(n) => {
                write!(f, "op-stream: {n} operands, schema allows at most 3")
            }
            Self::Truncated(what) => write!(f, "op-stream: truncated while reading {what}"),
            Self::AuxLengthMismatch { declared, present } => write!(
                f,
                "op-stream: auxLen declares {declared} bytes, {present} present"
            ),
            Self::TrailingBytes(n) => {
                write!(f, "op-stream: {n} bytes after a complete event")
            }
        }
    }
}

/// Decodes one event's `data` section.
///
/// Strict on every boundary. A consumer that tolerates a malformed event is a
/// consumer that silently disagrees with the chain about what work was ordered,
/// which the fraud game reads as dishonesty rather than as a bug.
pub fn decode(data: &[u8]) -> Result<StreamEvent, DecodeError> {
    let mut r = Reader { data, at: 0 };

    let version = r.u8("version")?;
    if version != ENVELOPE_VERSION {
        return Err(DecodeError::UnknownVersion(version));
    }
    let opcode = r.u8("opcode")?;
    let result_type = r.u8("resultType")?;
    let count = r.u8("operandCount")?;
    if count > 3 {
        return Err(DecodeError::TooManyOperands(count));
    }

    let mut operands = Vec::with_capacity(count as usize);
    for _ in 0..count {
        operands.push(r.word("operand")?);
    }
    let result_handle = r.word("resultHandle")?;
    let hcu_cost = r.u32("hcuCost")?;
    let aux_len = r.u16("auxLen")? as usize;

    let remaining = r.data.len() - r.at;
    if remaining < aux_len {
        return Err(DecodeError::AuxLengthMismatch {
            declared: aux_len,
            present: remaining,
        });
    }
    let aux = r.data[r.at..r.at + aux_len].to_vec();
    r.at += aux_len;

    if r.at != r.data.len() {
        return Err(DecodeError::TrailingBytes(r.data.len() - r.at));
    }

    Ok(StreamEvent {
        version,
        opcode,
        result_type,
        operands,
        result_handle,
        hcu_cost,
        aux,
    })
}

struct Reader<'a> {
    data: &'a [u8],
    at: usize,
}

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize, what: &'static str) -> Result<&'a [u8], DecodeError> {
        if self.data.len() - self.at < n {
            return Err(DecodeError::Truncated(what));
        }
        let s = &self.data[self.at..self.at + n];
        self.at += n;
        Ok(s)
    }
    fn u8(&mut self, what: &'static str) -> Result<u8, DecodeError> {
        Ok(self.take(1, what)?[0])
    }
    fn u16(&mut self, what: &'static str) -> Result<u16, DecodeError> {
        let b = self.take(2, what)?;
        Ok(u16::from_be_bytes([b[0], b[1]]))
    }
    fn u32(&mut self, what: &'static str) -> Result<u32, DecodeError> {
        let b = self.take(4, what)?;
        Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }
    fn word(&mut self, what: &'static str) -> Result<[u8; 32], DecodeError> {
        let b = self.take(32, what)?;
        let mut w = [0u8; 32];
        w.copy_from_slice(b);
        Ok(w)
    }
}
