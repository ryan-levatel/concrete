use crate::ciphertext::Ciphertext;
use crate::ServerKey;

impl ServerKey {
    /// Computes homomorphically a multiplication between a ciphertext encrypting an integer value
    /// and another encrypting a shortint value.
    ///
    /// This function computes the operation without checking if it exceeds the capacity of the
    /// ciphertext.
    ///
    /// The result is assigned to the `ct_left` ciphertext.
    ///
    /// # Example
    ///
    ///```rust
    /// use concrete_integer::gen_keys;
    /// use concrete_shortint::parameters::PARAM_MESSAGE_2_CARRY_2;
    /// let size = 4;
    ///
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys(&PARAM_MESSAGE_2_CARRY_2, size);
    ///
    /// let clear_1 = 170;
    /// let clear_2 = 3;
    ///
    /// // Encrypt two messages
    /// let mut ct_left = cks.encrypt(clear_1);
    /// let ct_right = cks.encrypt_one_block(clear_2);
    ///
    /// // Compute homomorphically a multiplication
    /// sks.unchecked_block_mul_assign(&mut ct_left, &ct_right, 0);
    ///
    /// // Decrypt
    /// let res = cks.decrypt(&ct_left);
    /// assert_eq!((clear_1 * clear_2) % 256, res);
    /// ```
    pub fn unchecked_block_mul_assign(
        &self,
        ct_left: &mut Ciphertext,
        ct_right: &concrete_shortint::Ciphertext,
        index: usize,
    ) {
        *ct_left = self.unchecked_block_mul(ct_left, ct_right, index);
    }

    /// Computes homomorphically a multiplication between a ciphertexts encrypting an integer
    /// value and another encrypting a shortint value.
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
    /// let size = 4;
    ///
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys(&PARAM_MESSAGE_2_CARRY_2, size);
    ///
    /// let clear_1 = 55;
    /// let clear_2 = 3;
    ///
    /// // Encrypt two messages
    /// let ct_left = cks.encrypt(clear_1);
    /// let ct_right = cks.encrypt_one_block(clear_2);
    ///
    /// // Compute homomorphically a multiplication
    /// let ct_res = sks.unchecked_block_mul(&ct_left, &ct_right, 0);
    ///
    /// // Decrypt
    /// let res = cks.decrypt(&ct_res);
    /// assert_eq!((clear_1 * clear_2) % 256, res);
    /// ```
    pub fn unchecked_block_mul(
        &self,
        ct1: &Ciphertext,
        ct2: &concrete_shortint::Ciphertext,
        index: usize,
    ) -> Ciphertext {
        let shifted_ct = self.blockshift(ct1, index);

        let mut result_lsb = shifted_ct.clone();
        let mut result_msb = shifted_ct;

        for res_lsb_i in result_lsb.ct_vec[index..].iter_mut() {
            self.key.unchecked_mul_lsb_assign(res_lsb_i, ct2);
        }

        let len = result_msb.ct_vec.len() - 1;
        for res_msb_i in result_msb.ct_vec[index..len].iter_mut() {
            self.key.unchecked_mul_msb_assign(res_msb_i, ct2);
        }

        result_msb = self.blockshift(&result_msb, 1);

        self.unchecked_add(&result_lsb, &result_msb)
    }

    /// Computes homomorphically a multiplication between a ciphertexts encrypting an integer
    /// value and another encrypting a shortint value.
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
    /// let size = 4;
    ///
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys(&PARAM_MESSAGE_2_CARRY_2, size);
    ///
    /// let clear_1 = 55;
    /// let clear_2 = 3;
    ///
    /// // Encrypt two messages
    /// let ct_left = cks.encrypt(clear_1);
    /// let ct_right = cks.encrypt_one_block(clear_2);
    ///
    /// // Compute homomorphically a multiplication
    /// let ct_res = sks.unchecked_multivalue_block_mul(&ct_left, &ct_right, 0);
    ///
    /// // Decrypt
    /// let res = cks.decrypt(&ct_res);
    /// assert_eq!((clear_1 * clear_2) % 256, res);
    /// ```
    pub fn unchecked_multivalue_block_mul(
        &self,
        ct1: &Ciphertext,
        ct2: &concrete_shortint::Ciphertext,
        index: usize,
    ) -> Ciphertext {
        let shifted_ct = self.blockshift(ct1, index);

        let mut result_lsb = shifted_ct.clone();
        let mut result_msb = shifted_ct;

        let len = result_msb.ct_vec.len() - 1;
        let modulus = (ct2.degree.0 + 1) as u64;

        // Modulus of the msg in the msg bits
        let res_modulus = self.key.message_modulus.0 as u64;
        let f_msb = |x| ((x / modulus) * (x % modulus)) / res_modulus;
        let f_lsb = |x| ((x / modulus) * (x % modulus)) % res_modulus;

        for (res_msb_i, res_lsb_i) in result_msb.ct_vec[index..len].iter_mut().zip(result_lsb.ct_vec[index..].iter_mut()) {
            self.key.concatenate_ciphertexts(res_lsb_i, ct2);
            let (r_lsb, r_msb) = self.key.bivaluepbs(res_lsb_i, f_lsb, f_msb);
            *res_msb_i = r_msb;
            *res_lsb_i = r_lsb;
        }

        for res_lsb_i in result_lsb.ct_vec[len..].iter_mut() {
            self.key.unchecked_mul_lsb_assign(res_lsb_i, ct2);
        }

        result_msb = self.blockshift(&result_msb, 1);

        self.unchecked_add(&result_lsb, &result_msb)
    }

    /// Computes homomorphically a multiplication between a ciphertext encrypting integer value
    /// and another encrypting a shortint value.
    ///
    /// The result is returned as a new ciphertext.
    ///
    /// # Example
    ///
    ///```rust
    /// use concrete_integer::gen_keys;
    /// use concrete_shortint::parameters::PARAM_MESSAGE_2_CARRY_2;
    /// let size = 4;
    ///
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys(&PARAM_MESSAGE_2_CARRY_2, size);
    ///
    /// let clear_1 = 170;
    /// let clear_2 = 3;
    ///
    /// // Encrypt two messages
    /// let mut ctxt_1 = cks.encrypt(clear_1);
    /// let ctxt_2 = cks.encrypt_one_block(clear_2);
    ///
    /// // Compute homomorphically a multiplication
    /// let ct_res = sks.smart_block_mul(&mut ctxt_1, &ctxt_2, 0);
    ///
    /// // Decrypt
    /// let res = cks.decrypt(&ct_res);
    /// assert_eq!((clear_1 * clear_2) % 256, res);
    /// ```
    pub fn smart_block_mul(
        &self,
        ct1: &mut Ciphertext,
        ct2: &concrete_shortint::Ciphertext,
        index: usize,
    ) -> Ciphertext {
        //Makes sure we can do the multiplications
        self.full_propagate(ct1);

        let shifted_ct = self.blockshift(ct1, index);

        let mut result_lsb = shifted_ct.clone();
        let mut result_msb = shifted_ct;

        for res_lsb_i in result_lsb.ct_vec[index..].iter_mut() {
            self.key.unchecked_mul_lsb_assign(res_lsb_i, ct2);
        }

        let len = result_msb.ct_vec.len() - 1;
        for res_msb_i in result_msb.ct_vec[index..len].iter_mut() {
            self.key.unchecked_mul_msb_assign(res_msb_i, ct2);
        }

        result_msb = self.blockshift(&result_msb, 1);

        self.smart_add(&mut result_lsb, &mut result_msb)
    }

    pub fn smart_block_mul_assign(
        &self,
        ct1: &mut Ciphertext,
        ct2: &concrete_shortint::Ciphertext,
        index: usize,
    ) {
        *ct1 = self.smart_block_mul(ct1, ct2, index);
    }


    pub fn smart_multivalue_block_mul(
        &self,
        ct1: &mut Ciphertext,
        ct2: &concrete_shortint::Ciphertext,
        index: usize,
    ) -> Ciphertext {
        //Makes sure we can do the multiplications
        self.multivalue_full_propagate(ct1);

        let shifted_ct = self.blockshift(ct1, index);

        let mut result_lsb = shifted_ct.clone();
        let mut result_msb = shifted_ct;

        let len = result_msb.ct_vec.len() - 1;
        let modulus = (ct2.degree.0 + 1) as u64;

        // Modulus of the msg in the msg bits
        let res_modulus = self.key.message_modulus.0 as u64;
        let f_msb = |x| ((x / modulus) * (x % modulus)) / res_modulus;
        let f_lsb = |x| ((x / modulus) * (x % modulus)) % res_modulus;

        for (res_msb_i, res_lsb_i) in result_msb.ct_vec[index..len].iter_mut().zip(result_lsb.ct_vec[index..].iter_mut()) {
            self.key.concatenate_ciphertexts(res_lsb_i, ct2);
            let (r_lsb, r_msb) = self.key.bivaluepbs(res_lsb_i, f_lsb, f_msb);
            *res_msb_i = r_msb;
            *res_lsb_i = r_lsb;
        }

        for res_lsb_i in result_lsb.ct_vec[len..].iter_mut() {
            self.key.unchecked_mul_lsb_assign(res_lsb_i, ct2);
        }

        result_msb = self.blockshift(&result_msb, 1);

        self.smart_multivalue_add(&mut result_lsb, &mut result_msb)
    }

    pub fn smart_multivalue_block_mul_assign(
        &self,
        ct1: &mut Ciphertext,
        ct2: &concrete_shortint::Ciphertext,
        index: usize,
    ) {
        *ct1 = self.smart_multivalue_block_mul(ct1, ct2, index);
    }

    /// Computes homomorphically a multiplication between two ciphertexts encrypting integer values.
    ///
    /// This function computes the operation without checking if it exceeds the capacity of the
    /// ciphertext.
    ///
    /// The result is assigned to the `ct_left` ciphertext.
    /// # Example
    ///
    /// ```rust
    /// use concrete_integer::gen_keys;
    /// use concrete_shortint::parameters::PARAM_MESSAGE_2_CARRY_2;
    /// let size = 4;
    ///
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys(&PARAM_MESSAGE_2_CARRY_2, size);
    ///
    /// let clear_1 = 255;
    /// let clear_2 = 143;
    ///
    /// // Encrypt two messages
    /// let mut ctxt_1 = cks.encrypt(clear_1);
    /// let ctxt_2 = cks.encrypt(clear_2);
    ///
    /// // Compute homomorphically a multiplication
    /// let ct_res = sks.unchecked_mul(&mut ctxt_1, &ctxt_2);
    ///
    /// // Decrypt
    /// let res = cks.decrypt(&ct_res);
    /// assert_eq!((clear_1 * clear_2) % 256, res);
    /// ```
    pub fn unchecked_mul_assign(&self, ct1: &mut Ciphertext, ct2: &Ciphertext) {
        *ct1 = self.unchecked_mul(ct1, ct2);
    }

    /// Computes homomorphically a multiplication between two ciphertexts encrypting integer values.
    ///
    /// This function computes the operation without checking if it exceeds the capacity of the
    /// ciphertext.
    ///
    /// The result is returned as a new ciphertext.
    pub fn unchecked_mul(&self, ct1: &mut Ciphertext, ct2: &Ciphertext) -> Ciphertext {
        let copy = ct1.clone();
        let mut result = self.create_trivial_zero(
            ct1.ct_vec.len(),
            ct1.message_modulus_vec.clone(),
            ct1.key_id_vec.clone(),
        );

        for (i, ct2_i) in ct2.ct_vec.iter().enumerate() {
            let tmp = self.unchecked_block_mul(&copy, ct2_i, i);

            self.unchecked_add_assign(&mut result, &tmp);
        }

        result
    }

    pub fn unchecked_multivalue_mul(&self, ct1: &mut Ciphertext, ct2: &Ciphertext) -> Ciphertext {
        let copy = ct1.clone();
        let mut result = self.create_trivial_zero(
            ct1.ct_vec.len(),
            ct1.message_modulus_vec.clone(),
            ct1.key_id_vec.clone(),
        );

        for (i, ct2_i) in ct2.ct_vec.iter().enumerate() {
            let tmp = self.unchecked_multivalue_block_mul(&copy, ct2_i, i);

            self.unchecked_add_assign(&mut result, &tmp);
        }

        result
    }

    pub fn unchecked_mutlivalue_mul_assign(&self, ct1: &mut Ciphertext, ct2: &Ciphertext) {
        *ct1 = self.unchecked_multivalue_mul(ct1, ct2);
    }

    /// Computes homomorphically a multiplication between two ciphertexts encrypting integer values.
    ///
    /// The result is assigned to the `ct_left` ciphertext.
    ///
    /// # Example
    ///
    /// ```rust
    /// use concrete_integer::gen_keys;
    /// use concrete_shortint::parameters::PARAM_MESSAGE_2_CARRY_2;
    /// let size = 4;
    ///
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys(&PARAM_MESSAGE_2_CARRY_2, size);
    ///
    /// let clear_1 = 170;
    /// let clear_2 = 6;
    ///
    /// // Encrypt two messages
    /// let mut ctxt_1 = cks.encrypt(clear_1);
    /// let mut ctxt_2 = cks.encrypt(clear_2);
    ///
    /// // Compute homomorphically a multiplication
    /// let ct_res = sks.smart_mul(&mut ctxt_1, &mut ctxt_2);
    /// // Decrypt
    /// let res = cks.decrypt(&ct_res);
    /// assert_eq!((clear_1 * clear_2) % 256, res);
    /// ```
    pub fn smart_mul_assign(&self, ct1: &mut Ciphertext, ct2: &mut Ciphertext) {
        *ct1 = self.smart_mul(ct1, ct2);
    }

    /// Computes homomorphically a multiplication between two ciphertexts encrypting integer values.
    ///
    /// The result is returned as a new ciphertext.
    pub fn smart_mul(&self, ct1: &mut Ciphertext, ct2: &mut Ciphertext) -> Ciphertext {
        self.full_propagate(ct1);
        self.full_propagate(ct2);

        let copy = ct1.clone();
        let mut result = self.create_trivial_zero(
            ct1.ct_vec.len(),
            ct1.message_modulus_vec.clone(),
            ct1.key_id_vec.clone(),
        );

        for (i, ct2_i) in ct2.ct_vec.iter().enumerate() {
            let mut tmp = self.unchecked_block_mul(&copy, ct2_i, i);
            self.smart_add_assign(&mut result, &mut tmp);
        }

        result
    }

    pub fn smart_multivalue_mul_assign(&self, ct1: &mut Ciphertext, ct2: &mut Ciphertext) {
        *ct1 = self.smart_multivalue_mul(ct1, ct2);
    }

    pub fn smart_multivalue_mul(&self, ct1: &mut Ciphertext, ct2: &mut Ciphertext) -> Ciphertext {
        self.multivalue_full_propagate(ct1);
        self.multivalue_full_propagate(ct2);

        let copy = ct1.clone();
        let mut result = self.create_trivial_zero(
            ct1.ct_vec.len(),
            ct1.message_modulus_vec.clone(),
            ct1.key_id_vec.clone(),
        );

        for (i, ct2_i) in ct2.ct_vec.iter().enumerate() {
            let mut tmp = self.unchecked_multivalue_block_mul(&copy, ct2_i, i);
            self.smart_multivalue_add_assign(&mut result, &mut tmp);
        }

        result
    }
}
