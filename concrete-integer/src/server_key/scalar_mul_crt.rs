use crate::ciphertext::Ciphertext;
use crate::server_key::CheckError;
use crate::server_key::CheckError::CarryFull;
use crate::ServerKey;
use std::collections::BTreeMap;

impl ServerKey {
    /// Computes homomorphically a multiplication between a scalar and a ciphertext.
    ///
    /// This function computes the operation without checking if it exceeds the capacity of the
    /// ciphertext.
    ///
    /// The result is returned as a new ciphertext.
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
    /// let clear_2 = 2;
    /// let basis = vec![2, 3, 5];
    /// // Encrypt two messages
    /// let mut ctxt_1 = cks.encrypt_crt(clear_1, basis.clone());
    ///
    /// sks.unchecked_crt_scalar_mul_assign(&mut ctxt_1, clear_2);
    ///
    /// // Decrypt
    /// let res = cks.decrypt_crt(&ctxt_1);
    /// assert_eq!((clear_1 * clear_2) % 30, res);
    /// ```
    pub fn unchecked_crt_scalar_mul(&self, ctxt: &Ciphertext, scalar: u64) -> Ciphertext {
        let mut ct_result = ctxt.clone();
        self.unchecked_crt_scalar_mul_assign(&mut ct_result, scalar);

        ct_result
    }

    pub fn unchecked_crt_scalar_mul_assign(&self, ctxt: &mut Ciphertext, scalar: u64) {
        for (ct_i, mod_i) in ctxt.ct_vec.iter_mut().zip(ctxt.message_modulus_vec.iter()) {
            self.key.unchecked_scalar_mul_assign(ct_i, (scalar % mod_i) as u8);
        }
    }

    ///Verifies if ct1 can be multiplied by scalar.
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
    /// let clear_2 = 2;
    /// let basis = vec![2, 3, 5];
    /// // Encrypt two messages
    /// let mut ctxt_1 = cks.encrypt_crt(clear_1, basis.clone());
    ///
    /// let tmp = sks.is_crt_scalar_mul_possible(&mut ctxt_1, clear_2);
    ///
    /// assert_eq!(true, tmp);
    /// ```
    pub fn is_crt_scalar_mul_possible(&self, ctxt: &Ciphertext, scalar: u64) -> bool {
        for (ct_i, mod_i) in ctxt.ct_vec.iter().zip(ctxt.message_modulus_vec.iter()) {
            if !self.key.is_scalar_mul_possible(ct_i, (scalar % mod_i) as u8) {
                return false;
            }
        }
        true
    }

    /// Computes homomorphically a multiplication between a scalar and a ciphertext.
    ///
    /// If the operation can be performed, the result is returned in a new ciphertext.
    /// Otherwise [CheckError::CarryFull] is returned.
    ///
    /// # Example
    ///
    /// ```rust
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// use concrete_integer::gen_keys;
    /// use concrete_shortint::parameters::PARAM_MESSAGE_2_CARRY_2;
    ///
    /// let size = 3;
    ///
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys(&PARAM_MESSAGE_2_CARRY_2, size);
    ///
    /// let clear_1 = 14;
    /// let clear_2 = 2;
    /// let basis = vec![2, 3, 5];
    /// // Encrypt two messages
    /// let mut ctxt_1 = cks.encrypt_crt(clear_1, basis.clone());
    ///
    /// sks.checked_crt_scalar_mul_assign(&mut ctxt_1, clear_2);
    ///
    /// // Decrypt
    /// let res = cks.decrypt_crt(&ctxt_1);
    /// assert_eq!((clear_1 * clear_2) % 30, res);
    /// # Ok(())
    /// # }
    /// ```
    pub fn checked_crt_scalar_mul(
        &self,
        ct: &Ciphertext,
        scalar: u64,
    ) -> Result<Ciphertext, CheckError> {
        let mut ct_result = ct.clone();

        // If the ciphertext cannot be multiplied without exceeding the capacity of a ciphertext
        if self.is_crt_scalar_mul_possible(ct, scalar) {
            ct_result = self.unchecked_crt_scalar_mul(&ct_result, scalar);

            Ok(ct_result)
        } else {
            Err(CarryFull)
        }
    }

    /// Computes homomorphically a multiplication between a scalar and a ciphertext.
    ///
    /// If the operation can be performed, the result is assigned to the ciphertext given
    /// as parameter.
    /// Otherwise [CheckError::CarryFull] is returned.
    pub fn checked_crt_scalar_mul_assign(
        &self,
        ct: &mut Ciphertext,
        scalar: u64,
    ) -> Result<(), CheckError> {
        // If the ciphertext cannot be multiplied without exceeding the capacity of a ciphertext
        if self.is_crt_scalar_mul_possible(ct, scalar) {
            self.unchecked_crt_scalar_mul_assign(ct, scalar);
            Ok(())
        } else {
            Err(CarryFull)
        }
    }

    /// Computes homomorphically a multiplication between a scalar and a ciphertext.
    ///
    /// `small` means the scalar value shall fit in a __shortint block__.
    /// For example, if the parameters are PARAM_MESSAGE_2_CARRY_2,
    /// the scalar should fit in 2 bits.
    ///
    /// The result is returned as a new ciphertext.
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
    ///
    /// let ctxt = sks.smart_crt_scalar_mul(&mut ctxt_1, clear_2);
    ///
    /// // Decrypt
    /// let res = cks.decrypt_crt(&ctxt);
    /// assert_eq!((clear_1 * clear_2) % 30, res);
    /// ```
    pub fn smart_crt_scalar_mul(&self, ctxt: &mut Ciphertext, scalar: u64) -> Ciphertext {
        if !self.is_crt_scalar_mul_possible(ctxt, scalar) {
            self.full_extract(ctxt);
        }
        self.unchecked_crt_scalar_mul(ctxt, scalar)
    }

    /// Computes homomorphically a multiplication between a scalar and a ciphertext.
    ///
    /// `small` means the scalar shall value fit in a __shortint block__.
    /// For example, if the parameters are PARAM_MESSAGE_2_CARRY_2,
    /// the scalar should fit in 2 bits.
    ///
    /// The result is assigned to the input ciphertext
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
    ///
    /// sks.smart_crt_scalar_mul_assign(&mut ctxt_1, clear_2);
    ///
    /// // Decrypt
    /// let res = cks.decrypt_crt(&ctxt_1);
    /// assert_eq!((clear_1 * clear_2) % 30, res);
    /// ```
    pub fn smart_crt_scalar_mul_assign(&self, ctxt: &mut Ciphertext, scalar: u64) {
        if !self.is_small_scalar_mul_possible(ctxt, scalar) {
            self.full_extract(ctxt);
        }
        self.unchecked_crt_scalar_mul_assign(ctxt, scalar);
    }
}
