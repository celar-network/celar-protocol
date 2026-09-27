//! Executing a decoded event against the pinned backend.
//! 
//! §8(ii) is the constraint that shapes this file: *"A coprocessor MUST NOT
//! optimise the op-stream — including optimisations that preserve the value…
//! Execute the stream exactly as emitted, op for op, whatever a compiler would
//! consider obviously safe."*

use std::collections::HashMap;
use celar_zama::backend::{Backend, FheError, Handle as BackendHandle};

use crate::ingest::StreamRef;
use crate::opstream::StreamEvent;

/// §3's opcode table.
pub mod op {
    pub const VERIFY_INPUT: u8 = 0x01;
    pub const TRIVIAL_ENCRYPT: u8 = 0x02;
    pub const ADD: u8 = 0x10;
    pub const SUB: u8 = 0x11;
    pub const LE: u8 = 0x12;
    pub const LT: u8 = 0x13;
    pub const EQ: u8 = 0x14;
    pub const AND: u8 = 0x18;
    pub const OR: u8 = 0x19;
    pub const NOT: u8 = 0x1A;
    pub const SELECT: u8 = 0x20;
    pub const CAST: u8 = 0x21;
    /// §3.4. Not an operation: the chain reporting that one died. It has
    /// carried this code since v0.1 in §6; §3's table omitted it until v0.10,
    /// which is why a consumer implementing §3 as normative met it as unknown.
    pub const ABORT: u8 = 0xF0;
}

pub type ChainHandle = [u8; 32];

#[derive(Debug)]
pub enum Outcome {
    Executed(BackendHandle),
    /// §3: bodies never ride the stream. Admission's aux carries a commitment
    /// and a DA pointer, so a consumer cannot admit until the data-availability
    /// layer exists. Reported
    /// as an outcome rather than an error: the stream is well formed and this
    /// consumer simply cannot follow it here yet.
    NeedsCiphertextBody { commitment: [u8; 32] },
    /// §3.4: the chain aborted an op. Nothing is executed and nothing is
    /// attested — the subject is another event, not this one.
    ///
    /// `resultHandle` carries the ABORTED op's handle rather than this event's
    /// result, which is opcode-dependent behaviour of that field and the one
    /// case where misreading it is silent: a consumer treating it as "the
    /// result of this event" would register a handle for an op that never ran.
    Aborted { aborted_at: StreamRef, aborted_handle: ChainHandle },
}

#[derive(Debug)]
pub enum ExecError {
    /// Inferred, not quoted: §3 mandates halting on an unknown *version* and is
    /// silent on an unknown opcode. An op we cannot name is work we cannot
    /// attest to.
    UnknownOpcode(u8),
    UnknownOperand(ChainHandle),
    WrongOperandCount { opcode: u8, want: usize, got: usize },
    Aux(&'static str),
    Backend(FheError),
}

impl From<FheError> for ExecError {
    fn from(e: FheError) -> Self {
        Self::Backend(e)
    }
}

#[derive(Default)]
pub struct Executor {
    backend: Backend,
    handles: HashMap<ChainHandle, BackendHandle>,
}

impl Executor {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn backend(&self) -> &Backend {
        &self.backend
    }

    pub fn resolve(&self, h: &ChainHandle) -> Option<BackendHandle> {
        self.handles.get(h).copied()
    }

    pub fn execute(&mut self, e: &StreamEvent) -> Result<Outcome, ExecError> {
        let want = |n: usize| -> Result<(), ExecError> {
            if e.operands.len() == n {
                Ok(())
            } else {
                Err(ExecError::WrongOperandCount {
                    opcode: e.opcode,
                    want: n,
                    got: e.operands.len(),
                })
            }
        };

        // Before the operand machinery: an abort is not an operation and the
        // operand rules do not apply to it.
        if e.opcode == op::ABORT {
            want(0)?;
            let aux: [u8; 16] = e.aux.as_slice().try_into().map_err(|_| {
                ExecError::Aux("abort aux is not a 16-byte stream reference")
            })?;
            return Ok(Outcome::Aborted {
                aborted_at: crate::preimage::stream_ref_from_bytes(&aux),
                aborted_handle: e.result_handle,
            });
        }

        let out = match e.opcode {
            op::VERIFY_INPUT => {
                if e.aux.len() < 32 {
                    return Err(ExecError::Aux("verifyInput aux shorter than a commitment"));
                }
                let mut c = [0u8; 32];
                c.copy_from_slice(&e.aux[..32]);
                return Ok(Outcome::NeedsCiphertextBody { commitment: c });
            }
            op::TRIVIAL_ENCRYPT => {
                want(0)?;
                if e.aux.len() != 9 {
                    return Err(ExecError::Aux("trivialEncrypt aux is not value(8)+width(1)"));
                }
                let mut v = [0u8; 8];
                v.copy_from_slice(&e.aux[..8]);
                self.backend.trivial_encrypt(u64::from_be_bytes(v), e.aux[8])?
            }
            op::CAST => {
                want(1)?;
                if e.aux.len() != 1 {
                    return Err(ExecError::Aux("cast aux is not a single width byte"));
                }
                let a = self.operand(e, 0)?;
                self.backend.cast(a, e.aux[0])?
            }
            op::NOT => {
                want(1)?;
                let a = self.operand(e, 0)?;
                self.backend.not(a)?
            }
            op::SELECT => {
                want(3)?;
                let c = self.operand(e, 0)?;
                let a = self.operand(e, 1)?;
                let b = self.operand(e, 2)?;
                self.backend.select(c, a, b)?
            }
            code => {
                want(2)?;
                let a = self.operand(e, 0)?;
                let b = self.operand(e, 1)?;
                match code {
                    op::ADD => self.backend.add(a, b)?,
                    op::SUB => self.backend.sub(a, b)?,
                    op::LE => self.backend.le(a, b)?,
                    op::LT => self.backend.lt(a, b)?,
                    op::EQ => self.backend.eq(a, b)?,
                    op::AND => self.backend.and(a, b)?,
                    op::OR => self.backend.or(a, b)?,
                    other => return Err(ExecError::UnknownOpcode(other)),
                }
            }
        };

        // Overwrites on a repeated handle rather than skipping the work.
        // Skipping would be safe in value terms and is still not done:
        // "execute the stream op for op" is literal, and a consumer that
        // decides when work is redundant has started optimising.
        self.handles.insert(e.result_handle, out);
        Ok(Outcome::Executed(out))
    }

    fn operand(&self, e: &StreamEvent, i: usize) -> Result<BackendHandle, ExecError> {
        self.resolve(&e.operands[i])
            .ok_or(ExecError::UnknownOperand(e.operands[i]))
    }
}
