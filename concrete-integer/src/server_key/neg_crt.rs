use crate::ciphertext::Ciphertext;
use crate::server_key::CheckError;
use crate::server_key::CheckError::CarryFull;
use crate::ServerKey;

impl ServerKey {
    /// Homomorphically computes the opposite of a ciphertext encrypting an integer message.
    ///
    /// # Example
    ///
    ///```rust
    /// use concrete_integer::gen_keys;
    /// use concrete_shortint::parameters::PARAM_MESSAGE_2_CARRY_2;
    ///
    /// let size = 3;
    ///
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys(&PARAM_MESSAGE_2_CARRY_2, size);
    ///
    /// let clear = 14_u64;
    /// let basis = vec![2, 3, 5];
    ///
    /// let mut ctxt = cks.encrypt_crt(clear, basis.clone());
    ///
    /// sks.smart_crt_neg_assign(&mut ctxt);
    ///
    /// // Decrypt
    /// let res = cks.decrypt_crt(&ctxt);
    /// assert_eq!(16, res);
    /// ```
    pub fn smart_crt_neg_assign(&self, ctxt: &mut Ciphertext) {
        if !self.is_neg_possible(ctxt) {
            self.full_extract(ctxt);
        }
        self.unchecked_neg_assign(ctxt);
    }

    pub fn smart_crt_neg(&self, ctxt: &mut Ciphertext) -> Ciphertext {
        if !self.is_neg_possible(ctxt) {
            self.full_extract(ctxt);
        }
        self.unchecked_neg(ctxt)
    }
}
