use crate::ciphertext::Ciphertext;
use crate::ServerKey;

impl ServerKey {
    /// Shifts the blocks to the right.
    ///
    /// The result is returned as a new ciphertext.
    ///
    /// # Example
    ///
    /// ```rust
    /// use concrete_integer::gen_keys;
    /// use concrete_shortint::parameters::PARAM_MESSAGE_2_CARRY_2;
    ///
    /// // We have 4 * 2 = 8 bits of message
    /// let size = 4;
    /// let (cks, sks) = gen_keys(&PARAM_MESSAGE_2_CARRY_2, size);
    ///
    /// let msg = 16;
    /// let shift = 2;
    ///
    /// // Encrypt two messages:
    /// let mut ct = cks.encrypt(msg);
    ///
    /// let ct_res = sks.blockshift_right(&mut ct, shift);
    ///
    /// let div = cks.parameters().message_modulus.0.pow(shift as u32) as u64;
    ///
    /// // Decrypt:
    /// let clear = cks.decrypt(&ct_res);
    /// assert_eq!(msg / div, clear);
    /// ```
    pub fn blockshift_right(&self, ctxt: &Ciphertext, shift: usize) -> Ciphertext {
        let mut result = self.create_trivial_zero(
            ctxt.ct_vec.len(),
            ctxt.message_modulus_vec.clone(),
            ctxt.key_id_vec.clone(),
        );

        let limit = result.ct_vec.len() - shift;

        for (res_i, c_i) in result.ct_vec[..limit]
            .iter_mut()
            .zip(ctxt.ct_vec[shift..].iter())
        {
            *res_i = c_i.clone();
        }

        result
    }

    pub fn blockshift_right_assign(&self, ctxt: &mut Ciphertext, shift: usize) {
        *ctxt = self.blockshift_right(ctxt, shift);
    }

    /// Computes homomorphically a right shift.
    ///
    /// The result is returned as a new ciphertext.
    ///
    /// # Example
    ///
    /// ```rust
    /// use concrete_integer::gen_keys;
    /// use concrete_shortint::parameters::PARAM_MESSAGE_2_CARRY_2;
    ///
    /// // We have 4 * 2 = 8 bits of message
    /// let size = 4;
    /// let (cks, sks) = gen_keys(&PARAM_MESSAGE_2_CARRY_2, size);
    ///
    /// let msg = 128;
    /// let shift = 2;
    ///
    /// let ct = cks.encrypt(msg);
    ///
    /// // Compute homomorphically a right shift:
    /// let ct_res = sks.unchecked_scalar_right_shift(&ct, shift);
    ///
    /// // Decrypt:
    /// let dec = cks.decrypt(&ct_res);
    /// assert_eq!(msg >> shift, dec);
    /// ```
    pub fn unchecked_scalar_right_shift(&self, ct: &Ciphertext, shift: usize) -> Ciphertext {
        let mut result = ct.clone();
        self.unchecked_scalar_right_shift_assign(&mut result, shift);
        result
    }

    /// Computes homomorphically a right shift.
    ///
    /// The result is returned as a new ciphertext.
    ///
    /// # Example
    ///
    /// ```rust
    /// use concrete_integer::gen_keys;
    /// use concrete_shortint::parameters::PARAM_MESSAGE_2_CARRY_2;
    ///
    /// // We have 4 * 2 = 8 bits of message
    /// let size = 4;
    /// let (cks, sks) = gen_keys(&PARAM_MESSAGE_2_CARRY_2, size);
    ///
    /// let msg = 18;
    /// let shift = 4;
    ///
    /// let mut ct = cks.encrypt(msg);
    ///
    /// // Compute homomorphically a right shift:
    /// sks.unchecked_scalar_right_shift_assign(&mut ct, shift);
    ///
    /// // Decrypt:
    /// let dec = cks.decrypt(&ct);
    /// assert_eq!(msg >> shift, dec);
    /// ```
    pub fn unchecked_scalar_right_shift_assign(&self, ct: &mut Ciphertext, shift: usize) {
        let tmp = self.key.message_modulus.0 as f64;

        //number of bits of message
        let nb_bits = tmp.log2() as usize;

        // 2^u = 2^{p*q+r} = 2^{p*(q+1)}*2^{r-p}
        let quotient = shift / nb_bits;

        //p-r
        let modified_remainder = nb_bits - (shift % nb_bits);

        //if r == 0
        if modified_remainder == nb_bits {
            self.full_propagate(ct);
            self.blockshift_right_assign(ct, quotient as usize);
        } else {
            // B/2^u = (B*2^{p-r}) / (2^{p*(q+1)})
            self.unchecked_scalar_left_shift_assign(ct, modified_remainder);

            // We partially propagate in order to not lose information
            self.partial_propagate(ct);
            self.blockshift_right_assign(ct, 1_usize);

            // We propagate the last block in order to not lose information
            self.propagate(ct, ct.ct_vec.len() - 2);
            self.blockshift_right_assign(ct, quotient as usize);
        }
    }

    pub fn unchecked_multivalue_scalar_right_shift_assign(&self, ct: &mut Ciphertext, shift: usize) {
        let tmp = self.key.message_modulus.0 as f64;

        //number of bits of message
        let nb_bits = tmp.log2() as usize;

        // 2^u = 2^{p*q+r} = 2^{p*(q+1)}*2^{r-p}
        let quotient = shift / nb_bits;

        //p-r
        let modified_remainder = nb_bits - (shift % nb_bits);

        //if r == 0
        if modified_remainder == nb_bits {
            self.multivalue_full_propagate(ct);
            self.blockshift_right_assign(ct, quotient as usize);
        } else {
            // B/2^u = (B*2^{p-r}) / (2^{p*(q+1)})
            self.unchecked_scalar_left_shift_assign(ct, modified_remainder);

            // We partially propagate in order to not lose information
            self.multivalue_partial_propagate(ct);
            self.blockshift_right_assign(ct, 1_usize);

            // We propagate the last block in order to not lose information
            self.multivalue_propagate(ct, ct.ct_vec.len() - 2);
            self.blockshift_right_assign(ct, quotient as usize);
        }
    }

    /// Propagates all carries except the last one.
    /// For development purpose only.
    fn partial_propagate(&self, ctxt: &mut Ciphertext) {
        let len = ctxt.ct_vec.len() - 1;
        for i in 0..len {
            self.propagate(ctxt, i);
        }
    }

    fn partial_multivalue_propagate(&self, ctxt: &mut Ciphertext) {
        let len = ctxt.ct_vec.len() - 1;
        for i in 0..len {
            self.multivalue_propagate(ctxt, i);
        }
    }

    /// Computes homomorphically a left shift by a scalar.
    ///
    /// The result is returned as a new ciphertext.
    ///
    /// # Example
    ///
    /// ```rust
    /// use concrete_integer::gen_keys;
    /// use concrete_shortint::parameters::PARAM_MESSAGE_2_CARRY_2;
    ///
    /// // We have 4 * 2 = 8 bits of message
    /// let size = 4;
    /// let (cks, sks) = gen_keys(&PARAM_MESSAGE_2_CARRY_2, size);
    ///
    /// let msg = 21;
    /// let shift = 2;
    ///
    /// let ct1 = cks.encrypt(msg);
    ///
    /// // Compute homomorphically a right shift:
    /// let ct_res = sks.unchecked_scalar_left_shift(&ct1, shift);
    ///
    /// // Decrypt:
    /// let dec = cks.decrypt(&ct_res);
    /// assert_eq!(msg << shift, dec);
    /// ```
    pub fn unchecked_scalar_left_shift(&self, ct_left: &Ciphertext, shift: usize) -> Ciphertext {
        let mut result = ct_left.clone();
        self.unchecked_scalar_left_shift_assign(&mut result, shift);
        result
    }

    /// Computes homomorphically a left shift by a scalar.
    ///
    /// The result is assigned in the input ciphertext
    ///
    /// # Example
    ///
    /// ```rust
    /// use concrete_integer::gen_keys;
    /// use concrete_shortint::parameters::PARAM_MESSAGE_2_CARRY_2;
    ///
    /// // We have 4 * 2 = 8 bits of message
    /// let size = 4;
    /// let (cks, sks) = gen_keys(&PARAM_MESSAGE_2_CARRY_2, size);
    ///
    /// let msg = 13;
    /// let shift = 2;
    ///
    /// let mut ct = cks.encrypt(msg);
    ///
    /// // Compute homomorphically a right shift:
    /// sks.unchecked_scalar_left_shift_assign(&mut ct, shift);
    ///
    /// // Decrypt:
    /// let dec = cks.decrypt(&ct);
    /// assert_eq!(msg << shift, dec);
    /// ```
    pub fn unchecked_scalar_left_shift_assign(&self, ct: &mut Ciphertext, shift: usize) {
        let tmp = 1_u64 << shift;
        self.smart_scalar_mul_assign(ct, tmp);
    }

    pub fn unchecked_multivalue_scalar_left_shift_assign(&self, ct: &mut Ciphertext, shift: usize) {
        let tmp = 1_u64 << shift;
        self.smart_multivalue_scalar_mul_assign(ct, tmp);
    }
}
