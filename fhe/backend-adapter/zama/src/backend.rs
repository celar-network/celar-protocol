//!Cipher store and the frozen ABI's compute operations
//! 
//! Handles are opaque references; ciphertext material never leaves this
//! store. Every operation is deterministic with respect to its inputs and 
//! the pinned backend, which the faud game depends on.

use std::collections::HashMap;

use tfhe::prelude::*;
use tfhe::{ClientKey, FheBool, FheUint64};

/// Opaque reference to ciphertext material. 32 bytes on chain; a counter here.
pub type Handle = u64;

/// Stored ciphertext. Encypted booleans and integers are distinct types,
/// so the tag is what stops an ebool being used where an euint is meant.
pub enum Ct{
    /// Encrypted unsigned integer, carrying its declared plaintext width
    Uint { ct: FheUint64, width: u8},
    /// Encrypted boolean, the result of comparisons and boolean combinators
    Bool(FheBool),
}

#[derive(Debug, PartialEq)]
pub enum FheError {
    UnknownHandle(Handle),
    ExpectedUint(Handle),
    ExpectedBool(Handle),
    Badwidth(u8),
    RangeCheckFailed,
    ProofRejected,
}

pub type Res<T> = Result<T, FheError>;

/// Ciphertext store plus the ABI operations over it.
#[derive(Default)]
pub struct Backend {
    store: HashMap<Handle, Ct>,
    next: Handle
}

impl Backend {
    pub fn new() -> Self {
        Self { store: HashMap::new(), next: 1 }
    }

    fn put(&mut self, ct: Ct) -> Handle {
        let h = self.next;
        self.next += 1; 
        self.store.insert(h,ct);
        h
    }

    fn uint(&self, h: Handle) -> Res<(&FheUint64, u8)> {
        match self.store.get(&h) {
            Some(Ct::Uint { ct, width }) => Ok((ct, *width)),
            Some(_) => Err(FheError::ExpectedUint(h)),
            None => Err(FheError::UnknownHandle(h)),
        }
    }

    fn boolean(&self, h: Handle) -> Res<&FheBool> {
        match self.store.get(&h) {
            Some(Ct::Bool(ct)) => Ok(ct),
            Some(_) => Err(FheError::ExpectedBool(h)),
            None => Err(FheError::UnknownHandle(h)),
        }
    }

    fn check_width(k: u8) -> Res<()> {
        matches!(k, 8 | 16 | 32 |64 )
        .then_some(())
        .ok_or(FheError::Badwidth(k))
    }

    fn mask(width: u8) -> u64 {
        if width >= 64 { u64::MAX } else { (1u64 << width) -1 }
    }

    // ---- input admission -------------------------------------------------

    /// Public constant to ciphertext. Trivial encryption carries no secrecy,
    /// which is correct here: the value is public by definition.
    pub fn trivial_encrypt(&mut self, value: u64, k: u8) -> Res<Handle> {
        Self::check_width(k)?;
        let ct = FheUint64::try_encrypt_trivial(value & Self::mask(k))
            .map_err(|_| FheError::RangeCheckFailed)?;
        Ok(self.put(Ct::Uint { ct, width: k }))
    }

    /// Real encryption under a client key. Devnet path only: production
    /// ciphertexts arrive from clients with an input proof.
    pub fn encrypt(&mut self, value: u64, k:u8, ck: &ClientKey) -> Res<Handle> {
        Self::check_width(k)?;
        if value > Self::mask(k) {
            return Err(FheError::RangeCheckFailed);
        }
        let ct = FheUint64::encrypt(value, ck);
        Ok(self.put(Ct::Uint { ct, width: k }))
    }

    // ---- arithmetic ----------------------------------------------------
    
    pub fn add(&mut self, a: Handle, b:Handle) -> Res<Handle> {
        let (x, w) = self.uint(a)?;
        let (y, _) = self.uint(b)?;
        let ct = x + y;
        Ok(self.put(Ct::Uint { ct, width: w}))
    }

    pub fn sub(&mut self, a: Handle, b: Handle) -> Res<Handle> {
        let (x, w) = self.uint(a)?;
        let (y,_) = self.uint(b)?;
        let ct = x - y;
        Ok(self.put(Ct::Uint { ct, width: w}))
    }

    // ---- comparison ( produce ebool )-------------------------------------
    pub fn le(&mut self, a: Handle, b: Handle) -> Res<Handle> {
        let (x, _) = self.uint(a)?;
        let (y, _) = self.uint(b)?;
        let ct = x.le(y);
        Ok(self.put(Ct::Bool(ct)))
    }
    
    pub fn lt(&mut self, a: Handle, b: Handle) -> Res<Handle> {
        let (x, _) = self.uint(a)?;
        let (y, _) = self.uint(b)?;
        let ct = x.lt(y);
        Ok(self.put(Ct::Bool(ct)))
    }

     pub fn eq(&mut self, a: Handle, b: Handle) -> Res<Handle> {
        let (x, _) = self.uint(a)?;
        let (y, _) = self.uint(b)?;
        let ct = x.eq(y);
        Ok(self.put(Ct::Bool(ct)))
    }
    
    // ---- boolean combinators --------------------------------------------
    pub fn and(&mut self, a:Handle, b: Handle) -> Res<Handle> {
        let ct = self.boolean(a)? & self.boolean(b)?;
        Ok(self.put(Ct::Bool(ct)))
    }

    pub fn or(&mut self, a: Handle, b: Handle) -> Res<Handle> {
        let ct = self.boolean(a)? | self.boolean(b)?;
        Ok(self.put(Ct::Bool(ct)))
    }

    pub fn not(&mut self, a: Handle) -> Res<Handle> {
        let ct = !self.boolean(a)?;
        Ok(self.put(Ct::Bool(ct)))
    }

    // ---- the branchless primitive ---------------------------------------

    /// The only path an encrypted pedicated may flow into. Both branches are
    /// evaluated; nothing about the condition is observable.
    pub fn select(&mut self, cond: Handle, a: Handle, b: Handle) -> Res<Handle> {
        let c = self.boolean(cond)?;
        let (x,w) = self.uint(a)?;
        let (y, _) = self.uint(b)?;
        let ct = c.if_then_else(x, y);
         Ok(self.put(Ct::Uint { ct, width: w }))
    }

    // ---- width change ---------------------------------------------------

    pub fn cast(&mut self, a: Handle, k: u8) -> Res<Handle> {
        Self::check_width(k)?;
        let (x,_) = self.uint(a)?;
        let ct = x & Self::mask(k);
        Ok(self.put(Ct::Uint { ct, width:k}))
    }

    // ---- test/oracle path
    /// Decrypt for correctness comparison. Never a production path: real
    /// decryption goes through the threshold committee.
    pub fn oracle_uint(&self, h: Handle, ck: &ClientKey) -> Res<u64> {
        let (ct, _) = self.uint(h)?;
        Ok(ct.decrypt(ck))
    }

    pub fn oracle_bool(&self, h: Handle, ck: &ClientKey) -> Res<bool> {
        Ok(self.boolean(h)?.decrypt(ck))
    }
} 