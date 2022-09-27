use crate::ciphertext::Ciphertext;
use crate::server_key::CheckError;
use crate::server_key::CheckError::CarryFull;
use crate::ServerKey;

impl ServerKey {
    /// Computes homomorphically an addition between two ciphertexts encrypting integer values.
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
    /// let clear_1 = 14;
    /// let clear_2 = 14;
    /// let basis = vec![2, 3, 5];
    /// // Encrypt two messages
    /// let mut ctxt_1 = cks.encrypt_crt(clear_1, basis.clone());
    /// let mut ctxt_2 = cks.encrypt_crt(clear_2, basis);
    ///
    /// sks.smart_crt_add_assign(&mut ctxt_1, &mut ctxt_2);
    ///
    /// // Decrypt
    /// let res = cks.decrypt_crt(&ctxt_1);
    /// assert_eq!((clear_1 + clear_2) % 30, res);
    /// ```
    pub fn smart_crt_add(&self, ct_left: &mut Ciphertext, ct_right: &mut Ciphertext) -> Ciphertext {
        let mut result = ct_left.clone();

        self.smart_crt_add_assign(&mut result, ct_right);

        result
    }

    pub fn smart_crt_add_assign(&self, ct_left: &mut Ciphertext, ct_right: &mut Ciphertext) {
        //If the ciphertext cannot be added together without exceeding the capacity of a ciphertext
        if !self.is_add_possible(ct_left, ct_right) {
            self.full_extract(ct_left);
            self.full_extract(ct_right);
        }
        self.unchecked_add_assign(ct_left, ct_right);
    }
}
