use crate::ciphertext::RadixCiphertext;
use crate::ServerKey;

impl ServerKey {
    /// Computes homomorphically the subtraction between ct_left and ct_right.
    ///
    /// # Example
    ///
    /// ```rust
    /// use concrete_integer::gen_keys_radix;
    /// use concrete_shortint::parameters::PARAM_MESSAGE_2_CARRY_2;
    ///
    /// // We have 4 * 2 = 8 bits of message
    /// let size = 4;
    /// let (cks, sks) = gen_keys_radix(&PARAM_MESSAGE_2_CARRY_2, size);
    ///
    /// let msg_1 = 120u8;
    /// let msg_2 = 181u8;
    ///
    /// // Encrypt two messages:
    /// let mut ctxt_1 = cks.encrypt(msg_1 as u64);
    /// let mut ctxt_2 = cks.encrypt(msg_2 as u64);
    ///
    /// // Compute homomorphically a subtraction
    /// let ct_res = sks.smart_sub_parallelized(&mut ctxt_1, &mut ctxt_2);
    ///
    /// // Decrypt:
    /// let res = cks.decrypt(&ct_res);
    /// assert_eq!(msg_1.wrapping_sub(msg_2) as u64, res);
    /// ```
    pub fn smart_sub_parallelized(
        &self,
        ctxt_left: &mut RadixCiphertext,
        ctxt_right: &mut RadixCiphertext,
    ) -> RadixCiphertext {
        // If the ciphertext cannot be negated without exceeding the capacity of a ciphertext
        if !self.is_neg_possible(ctxt_right) {
            self.full_propagate_parallelized(ctxt_right);
        }

        // If the ciphertext cannot be added together without exceeding the capacity of a ciphertext
        if !self.is_sub_possible(ctxt_left, ctxt_right) {
            rayon::join(
                || self.full_propagate_parallelized(ctxt_left),
                || self.full_propagate_parallelized(ctxt_right),
            );
        }

        let mut result = ctxt_left.clone();
        self.unchecked_sub_assign(&mut result, ctxt_right);

        result
    }

    /// Computes homomorphically the subtraction between ct_left and ct_right.
    ///
    /// # Example
    ///
    /// ```rust
    /// use concrete_integer::gen_keys_radix;
    /// use concrete_shortint::parameters::PARAM_MESSAGE_2_CARRY_2;
    ///
    /// // We have 4 * 2 = 8 bits of message
    /// let size = 4;
    /// let (cks, sks) = gen_keys_radix(&PARAM_MESSAGE_2_CARRY_2, size);
    ///
    /// let msg_1 = 120u8;
    /// let msg_2 = 181u8;
    ///
    /// // Encrypt two messages:
    /// let mut ctxt_1 = cks.encrypt(msg_1 as u64);
    /// let mut ctxt_2 = cks.encrypt(msg_2 as u64);
    ///
    /// // Compute homomorphically a subtraction
    /// sks.smart_sub_assign_parallelized(&mut ctxt_1, &mut ctxt_2);
    ///
    /// // Decrypt:
    /// let res = cks.decrypt(&ctxt_1);
    /// assert_eq!(msg_1.wrapping_sub(msg_2) as u64, res);
    /// ```
    pub fn smart_sub_assign_parallelized(
        &self,
        ctxt_left: &mut RadixCiphertext,
        ctxt_right: &mut RadixCiphertext,
    ) {
        // If the ciphertext cannot be negated without exceeding the capacity of a ciphertext
        if !self.is_neg_possible(ctxt_right) {
            self.full_propagate_parallelized(ctxt_right);
        }

        // If the ciphertext cannot be added together without exceeding the capacity of a ciphertext
        if !self.is_sub_possible(ctxt_left, ctxt_right) {
            rayon::join(
                || self.full_propagate_parallelized(ctxt_left),
                || self.full_propagate_parallelized(ctxt_right),
            );
        }

        self.unchecked_sub_assign(ctxt_left, ctxt_right);
    }
}
