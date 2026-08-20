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
    MalformedCiphertext,
    MissingRecipientKey,
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
// ---------------------------------------------------------------------------
// Input admission and the KMS-facing paths.
//
// Two boundaries are deliberately stubbed here and owned by other tracks:
// input-proof verification (the admission gate) and threshold decryption /
// re-encryption (the committee). What belongs to this crate is the backend
// half: deserialising real ciphertext material and performing the underlying
// crypto. The stand-ins below are single-key and are never a production path.
// ---------------------------------------------------------------------------

impl Backend {
    /// Serialise a stored ciphertext. Clients use this shape to submit
    /// inputs; tests use it to round-trip through `verify_input`.
    pub fn serialize_handle(&self, h: Handle) -> Res<Vec<u8>> {
        let (ct, _) = self.uint(h)?;
        bincode::serialize(ct).map_err(|_| FheError::MalformedCiphertext)
    }

    /// Digest basis for op-stream attestation (protocol v0.4).
    ///
    /// v0.4 defines `ctDigest` over the integer-domain ciphertext,
    /// excluding the high-level wrapper's `id`, `tag` and
    /// `re_randomization_metadata`. Those last two are
    /// application-settable and serialised, so a digest over the
    /// wrapper would let two honest coprocessors produce different
    /// digests from identical computation — which is exactly the
    /// disagreement the fraud game cannot distinguish from cheating.
    ///
    /// Deliberately NOT folded into `serialize_handle`: that is the
    /// *wire* shape clients submit and tests round-trip through
    /// `verify_input`, and it must keep carrying the whole wrapper.
    /// Two different jobs, two functions.
    ///
    /// `into_raw_parts` consumes the value, so this clones. The cost
    /// is paid once per attested result, not per operation.
    pub fn digest_basis(&self, h: Handle) -> Res<Vec<u8>> {
        let (ct, _) = self.uint(h)?;
        let (radix, _id, _tag, _rerand) = ct.clone().into_raw_parts();
        bincode::serialize(&radix).map_err(|_| FheError::MalformedCiphertext)
    }

    /// Admit a client-supplied ciphertext.
    ///
    /// The proof check is a placeholder: a real input proof establishes
    /// well-formedness, range, and knowledge of the plaintext, and is the
    /// gate that keeps malformed ciphertext out of consensus state. Until
    /// that lands, an empty proof is refused and anything else accepted,
    /// which is enough to exercise the admission path without pretending to
    /// verify anything.
    pub fn verify_input(&mut self, ciphertext: &[u8], proof: &[u8]) -> Res<Handle> {
        if proof.is_empty() {
            return Err(FheError::ProofRejected);
        }
        let ct: FheUint64 = bincode::deserialize(ciphertext)
            .map_err(|_| FheError::MalformedCiphertext)?;
        Ok(self.put(Ct::Uint { ct, width: 64 }))
    }

    /// Stand-in for threshold decryption. The committee threshold is
    /// accepted and recorded but not enforced: real decryption combines
    /// partials from a quorum and never reconstructs a single key.
    pub fn threshold_decrypt(&self, h: Handle, _t: u32, ck: &ClientKey) -> Res<u64> {
        let (ct, _) = self.uint(h)?;
        Ok(ct.decrypt(ck))
    }

    /// Stand-in for threshold re-encryption toward a recipient's key.
    ///
    /// The output is bound to the recipient, which is the property that
    /// matters: material produced for one recipient must be useless to
    /// another. Real re-encryption produces partials that the recipient
    /// combines client-side; the plaintext exists only on their device.
    pub fn threshold_reencrypt(
        &self,
        h: Handle,
        _t: u32,
        user_pubkey: &[u8],
        ck: &ClientKey,
    ) -> Res<Vec<u8>> {
        if user_pubkey.is_empty() {
            return Err(FheError::MissingRecipientKey);
        }
        let (ct, _) = self.uint(h)?;
        let value: u64 = ct.decrypt(ck);
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(value.to_be_bytes());
        hasher.update(user_pubkey);
        Ok(hasher.finalize().to_vec())
    }
}
