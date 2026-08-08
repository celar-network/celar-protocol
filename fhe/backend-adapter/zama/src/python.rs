//! Python binding: exposes the backend to the bake-off harness.
//! the same correctness checks and the same report code produce measured
//! numbers instead of modelled ones.

use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use tfhe::{set_server_key, ClientKey};

use crate::backend::{Backend, FheError, Handle};
use crate::dev_keys;

impl From<FheError> for PyErr {
    fn from(e: FheError) -> Self {
        PyValueError::new_err(format!("{e:?}"))
    }
}

/// The same/TFHE-rs backend, as seen from python.
#[pyclass]
pub struct ZamaBackend {
    inner: Backend,
    ck: ClientKey,
}

#[pymethods]
impl ZamaBackend {
    ///Generate a fresh key pair and install the server key on this thread.
    /// Develpment path onlu: production keys come from the ceremony.
    #[new]
    fn new() -> Self {
        let(ck,sk) = dev_keys();
        set_server_key(sk);
        Self { inner: Backend::new(), ck }
    }

    // ---- input admission -------------------------------------------------------
    fn verify_input(&mut self, ciphertext: &[u8], proof: &[u8]) -> PyResult<Handle> {
        Ok(self.inner.verify_input(ciphertext, proof)?)
    }

    fn trivial_encrypt(&mut self, value:u64, k:u8) -> PyResult<Handle> {
        Ok(self.inner.trivial_encrypt(value, k)?)
    }

    /// Encrypt and serialise, so the harness can build a submission the wat
    /// a client would.
     fn encode_input(&mut self, value: u64, k: u8) -> PyResult<Vec<u8>> {
        let h = self.inner.encrypt(value, k, &self.ck)?;
        Ok(self.inner.serialize_handle(h)?)
    }

    fn add(&mut self, a: Handle, b: Handle) -> PyResult<Handle> {
        Ok(self.inner.add(a, b)?)
    }
    fn sub(&mut self, a: Handle, b: Handle) -> PyResult<Handle> {
        Ok(self.inner.sub(a, b)?)
    }
    fn le(&mut self, a: Handle, b: Handle) -> PyResult<Handle> {
        Ok(self.inner.le(a, b)?)
    }
    fn lt(&mut self, a: Handle, b: Handle) -> PyResult<Handle> {
        Ok(self.inner.lt(a, b)?)
    }
    fn eq(&mut self, a: Handle, b: Handle) -> PyResult<Handle> {
        Ok(self.inner.eq(a, b)?)
    }
    fn and_(&mut self, a: Handle, b: Handle) -> PyResult<Handle> {
        Ok(self.inner.and(a, b)?)
    }
    fn or_(&mut self, a: Handle, b: Handle) -> PyResult<Handle> {
        Ok(self.inner.or(a, b)?)
    }
    fn not_(&mut self, a: Handle) -> PyResult<Handle> {
        Ok(self.inner.not(a)?)
    }
    fn select(&mut self, cond: Handle, a: Handle, b: Handle) -> PyResult<Handle> {
        Ok(self.inner.select(cond, a, b)?)
    }
    fn cast(&mut self, a: Handle, k: u8) -> PyResult<Handle> {
        Ok(self.inner.cast(a, k)?)
    }

    /// A bootstrap-bearing operation, used as the performance probe.
    ///
    /// Comparison is the honest choice: every confidential transfer depends
    /// on it, and it is what separates schemes. The operand must be compared
    /// against a DISTINCT ciphertext — comparing a handle with itself is
    /// short-circuited by the library and measures nothing (observed 380x
    /// faster than a genuine comparison).
    fn pbs_op(&mut self, a: Handle) -> PyResult<Handle> {
        let other = self.inner.trivial_encrypt(1, 64)?;
        Ok(self.inner.le(a, other)?)
    }

    // ---- committee-facing ------------------------------------------------

    fn threshold_decrypt(&mut self, h: Handle, t: u32) -> PyResult<u64> {
        Ok(self.inner.threshold_decrypt(h, t, &self.ck)?)
    }

    fn threshold_reencrypt(
        &mut self,
        h: Handle,
        t: u32,
        user_pubkey: &[u8],
    ) -> PyResult<Vec<u8>> {
        Ok(self.inner.threshold_reencrypt(h, t, user_pubkey, &self.ck)?)
    }

    /// Plaintext shadow for oracle comparison. Booleans surface as 0/1 so
    /// the harness can compare them uniformly with integers.
    fn _oracle(&mut self, h: Handle) -> PyResult<u64> {
        match self.inner.oracle_uint(h, &self.ck) {
            Ok(v) => Ok(v),
            Err(_) => Ok(self.inner.oracle_bool(h, &self.ck)? as u64),
        }
    }

}
#[pymodule]
fn celar_zama(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<ZamaBackend>()?;
    m.add("BACKEND_NAME", crate::BACKEND_NAME)?;
    Ok(())
}


