//! This module implements the generation of the client keys structs
//!
//! Client keys are the keys used to encrypt an decrypt data.
//! The are private and **MUST NOT** be shared.

mod crt;
pub(crate) mod multi_crt;
mod radix;
pub(crate) mod utils;

use crate::ciphertext::{CrtCiphertext, RadixCiphertext};
use crate::client_key::utils::i_crt;
use concrete_shortint::parameters::MessageModulus;
use serde::{Deserialize, Serialize};
pub use utils::radix_decomposition;

pub use crt::CrtClientKey;
pub use multi_crt::CrtMultiClientKey;
pub use radix::RadixClientKey;

/// A structure containing the client key, which must be kept secret.
///
/// This key can be used to encrypt both in Radix and CRT
/// decompositions.
///
/// Using this key, for both decompositions, each block will
/// use the same crypto parameters.
#[derive(Serialize, Deserialize, PartialEq, Debug, Clone)]
pub struct ClientKey {
    pub(crate) key: concrete_shortint::ClientKey,
}

impl From<concrete_shortint::ClientKey> for ClientKey {
    fn from(key: concrete_shortint::ClientKey) -> Self {
        Self { key }
    }
}

impl From<ClientKey> for concrete_shortint::ClientKey {
    fn from(key: ClientKey) -> concrete_shortint::ClientKey {
        key.key
    }
}

impl AsRef<ClientKey> for ClientKey {
    fn as_ref(&self) -> &ClientKey {
        self
    }
}

impl ClientKey {
    /// Creates a Client Key.
    ///
    /// # Example
    ///
    /// ```rust
    /// use concrete_integer::ClientKey;
    /// use concrete_shortint::parameters::PARAM_MESSAGE_2_CARRY_2;
    ///
    /// // Generate the client key, that can encrypt in
    /// // radix and crt decomposition, where each block of the composition
    /// // have over 2 bits of message modulus.
    /// let cks = ClientKey::new(PARAM_MESSAGE_2_CARRY_2);
    /// ```
    pub fn new(parameter_set: concrete_shortint::Parameters) -> Self {
        Self {
            key: concrete_shortint::ClientKey::new(parameter_set),
        }
    }

    pub fn parameters(&self) -> concrete_shortint::Parameters {
        self.key.parameters
    }

    /// Encrypts an integer in radix decomposition
    ///
    /// # Example
    ///
    /// ```rust
    /// use concrete_integer::ClientKey;
    /// use concrete_shortint::parameters::PARAM_MESSAGE_2_CARRY_2;
    ///
    /// let cks = ClientKey::new(PARAM_MESSAGE_2_CARRY_2);
    /// let num_block = 4;
    ///
    /// let msg = 167_u64;
    ///
    /// // 2 * 4 = 8 bits of message
    /// let ct = cks.encrypt_radix(msg, num_block);
    ///
    /// // Decryption
    /// let dec = cks.decrypt_radix(&ct);
    /// assert_eq!(msg, dec);
    /// ```
    pub fn encrypt_radix(&self, message: u64, num_blocks: usize) -> RadixCiphertext {
        let mut blocks = Vec::with_capacity(num_blocks);

        // Bits of message put to 1
        let mask = (self.key.parameters.message_modulus.0 - 1) as u64;

        let mut power = 1_u64;
        // Put each decomposition into a new ciphertext
        for _ in 0..num_blocks {
            let decomp = (message & (mask * power)) / power;

            let ct = self.key.encrypt(decomp);
            blocks.push(ct);

            // modulus to the power i
            power *= self.key.parameters.message_modulus.0 as u64;
        }

        RadixCiphertext { blocks }
    }

    /// Encrypts an integer in radix decomposition without padding bit
    ///
    /// # Example
    ///
    /// ```rust
    /// use concrete_integer::ClientKey;
    /// use concrete_shortint::parameters::PARAM_MESSAGE_2_CARRY_2;
    ///
    /// let cks = ClientKey::new(PARAM_MESSAGE_2_CARRY_2);
    /// let num_block = 4;
    ///
    /// let msg = 167_u64;
    ///
    /// // 2 * 4 = 8 bits of message
    /// let ct = cks.encrypt_radix_without_padding(msg, num_block);
    ///
    /// // Decryption
    /// let dec = cks.decrypt_radix_without_padding(&ct);
    /// assert_eq!(msg, dec);
    /// ```
    pub fn encrypt_radix_without_padding(
        &self,
        message: u64,
        num_blocks: usize,
    ) -> RadixCiphertext {
        let mut blocks = Vec::with_capacity(num_blocks);

        // Bits of message put to 1
        let mask = (self.key.parameters.message_modulus.0 - 1) as u64;

        let mut power = 1_u64;
        // Put each decomposition into a new ciphertext
        for _ in 0..num_blocks {
            let decomp = (message & (mask * power)) / power;

            // encryption
            let ct = self.key.encrypt_without_padding(decomp);
            blocks.push(ct);

            // modulus to the power i
            power *= self.key.parameters.message_modulus.0 as u64;
        }

        RadixCiphertext { blocks }
    }

    /// Encrypts one block.
    ///
    /// This returns a shortint ciphertext.
    ///
    /// # Example
    ///
    /// ```rust
    /// use concrete_integer::ClientKey;
    /// use concrete_shortint::parameters::PARAM_MESSAGE_2_CARRY_2;
    ///
    /// let cks = ClientKey::new(PARAM_MESSAGE_2_CARRY_2);
    /// let num_block = 4;
    ///
    /// let msg = 2_u64;
    ///
    /// // Encryption
    /// let ct = cks.encrypt_one_block(msg);
    ///
    /// // Decryption
    /// let dec = cks.decrypt_one_block(&ct);
    /// assert_eq!(msg, dec);
    /// ```
    pub fn encrypt_one_block(&self, message: u64) -> concrete_shortint::Ciphertext {
        self.key.encrypt(message)
    }

    /// Decrypts one block.
    ///
    /// This takes a shortint ciphertext as input.
    pub fn decrypt_one_block(&self, ct: &concrete_shortint::Ciphertext) -> u64 {
        self.key.decrypt(ct)
    }

    /// Decrypts a ciphertext encrypting an radix integer
    ///
    /// # Example
    ///
    /// ```rust
    /// use concrete_integer::ClientKey;
    /// use concrete_shortint::parameters::PARAM_MESSAGE_2_CARRY_2;
    ///
    /// let cks = ClientKey::new(PARAM_MESSAGE_2_CARRY_2);
    /// let num_block = 4;
    ///
    /// let msg = 191_u64;
    ///
    /// // Encryption
    /// let ct = cks.encrypt_radix(msg, num_block);
    ///
    /// // Decryption
    /// let dec = cks.decrypt_radix(&ct);
    /// assert_eq!(msg, dec);
    /// ```
    pub fn decrypt_radix(&self, ctxt: &RadixCiphertext) -> u64 {
        let mut result = 0_u64;
        let mut shift = 1_u64;
        let modulus = self.parameters().message_modulus.0 as u64;

        for c_i in ctxt.blocks.iter() {
            // decrypt the component i of the integer and multiply it by the radix product
            let block_value = self.key.decrypt_message_and_carry(c_i).wrapping_mul(shift);

            // update the result
            result = result.wrapping_add(block_value);

            // update the shift for the next iteration
            shift = shift.wrapping_mul(modulus);
        }

        let whole_modulus = modulus.pow(ctxt.blocks.len() as u32);

        result % whole_modulus
    }

    /// Decrypts a ciphertext encrypting an radix integer encrypted without padding
    ///
    /// # Example
    ///
    /// ```rust
    /// use concrete_integer::ClientKey;
    /// use concrete_shortint::parameters::PARAM_MESSAGE_2_CARRY_2;
    ///
    /// let cks = ClientKey::new(PARAM_MESSAGE_2_CARRY_2);
    /// let num_block = 4;
    ///
    /// let msg = 191_u64;
    ///
    /// // Encryption
    /// let ct = cks.encrypt_radix_without_padding(msg, num_block);
    ///
    /// // Decryption
    /// let dec = cks.decrypt_radix_without_padding(&ct);
    /// assert_eq!(msg, dec);
    /// ```
    pub fn decrypt_radix_without_padding(&self, ctxt: &RadixCiphertext) -> u64 {
        let mut result = 0_u64;
        let mut shift = 1_u64;
        let modulus = self.parameters().message_modulus.0 as u64;
        for c_i in ctxt.blocks.iter() {
            // decrypt the component i of the integer and multiply it by the radix product
            let block_value = self
                .key
                .decrypt_message_and_carry_without_padding(c_i)
                .wrapping_mul(shift);

            // update the result
            result = result.wrapping_add(block_value);

            // update the shift for the next iteration
            shift = shift.wrapping_mul(modulus);
        }

        let whole_modulus = modulus.pow(ctxt.blocks.len() as u32);

        result % whole_modulus
    }

    /// Encrypts an integer using crt representation
    ///
    /// # Example
    ///
    /// ```rust
    /// use concrete_integer::ClientKey;
    /// use concrete_shortint::parameters::PARAM_MESSAGE_2_CARRY_2;
    ///
    /// let cks = ClientKey::new(PARAM_MESSAGE_2_CARRY_2);
    ///
    /// let msg = 13_u64;
    ///
    /// // Encryption:
    /// let basis: Vec<u64> = vec![2, 3, 5];
    /// let ct = cks.encrypt_crt(msg, basis);
    ///
    /// // Decryption:
    /// let dec = cks.decrypt_crt(&ct);
    /// assert_eq!(msg, dec);
    /// ```
    pub fn encrypt_crt(&self, message: u64, base_vec: Vec<u64>) -> CrtCiphertext {
        let mut ctxt_vect = Vec::with_capacity(base_vec.len());

        // Put each decomposition into a new ciphertext
        for modulus in base_vec.iter().copied() {
            // encryption
            let ct = self
                .key
                .encrypt_with_message_modulus(message, MessageModulus(modulus as usize));

            ctxt_vect.push(ct);
        }

        CrtCiphertext {
            blocks: ctxt_vect,
            moduli: base_vec,
        }
    }

    /// Decrypts an integer in crt decomposition
    ///
    /// # Example
    ///
    /// ```rust
    /// use concrete_integer::ClientKey;
    /// use concrete_shortint::parameters::PARAM_MESSAGE_2_CARRY_2;
    ///
    /// // Generate the client key and the server key:
    /// let mut cks = ClientKey::new(PARAM_MESSAGE_2_CARRY_2);
    ///
    /// let msg = 27_u64;
    /// let basis: Vec<u64> = vec![2, 3, 5];
    ///
    /// // Encryption:
    /// let mut ct = cks.encrypt_crt(msg, basis);
    ///
    /// // Decryption:
    /// let dec = cks.decrypt_crt(&ct);
    /// assert_eq!(msg, dec);
    /// ```
    pub fn decrypt_crt(&self, ctxt: &CrtCiphertext) -> u64 {
        let mut val: Vec<u64> = Vec::with_capacity(ctxt.blocks.len());

        // Decrypting each block individually
        for (c_i, b_i) in ctxt.blocks.iter().zip(ctxt.moduli.iter()) {
            // decrypt the component i of the integer and multiply it by the radix product
            val.push(self.key.decrypt_message_and_carry(c_i) % b_i);
        }

        // Computing the inverse CRT to recompose the message
        let result = i_crt(&ctxt.moduli, &val);

        let whole_modulus: u64 = ctxt.moduli.iter().copied().product();

        result % whole_modulus
    }

    /// Encrypts a small integer message using the client key and some moduli without padding bit.
    ///
    /// # Example
    ///
    /// ```rust
    /// use concrete_integer::ClientKey;
    /// use concrete_shortint::parameters::PARAM_MESSAGE_3_CARRY_3;
    ///
    /// let cks = ClientKey::new(PARAM_MESSAGE_3_CARRY_3);
    ///
    /// let msg = 13_u64;
    ///
    /// // Encryption of one message:
    /// let basis: Vec<u64> = vec![2, 3, 5];
    /// let ct = cks.encrypt_crt_not_power_of_two(msg, basis);
    ///
    /// // Decryption:
    /// let dec = cks.decrypt_crt_not_power_of_two(&ct);
    /// assert_eq!(msg, dec);
    /// ```
    pub fn encrypt_crt_not_power_of_two(&self, message: u64, base_vec: Vec<u64>) -> CrtCiphertext {
        //Empty vector of ciphertexts
        let mut ct_vec = Vec::with_capacity(base_vec.len());

        //Put each decomposition into a new ciphertext
        for modulus in base_vec.iter() {
            // encryption
            let ct = self
                .key
                .encrypt_with_message_modulus_not_power_of_two(message, *modulus as u8);

            // put it in the vector of ciphertexts
            ct_vec.push(ct);
        }

        CrtCiphertext {
            blocks: ct_vec,
            moduli: base_vec,
        }
    }

    /// Decrypts a ciphertext encrypting an integer message with some moduli basis without
    /// padding bit.
    ///
    /// # Example
    ///
    /// ```rust
    /// use concrete_integer::ClientKey;
    /// use concrete_shortint::parameters::PARAM_MESSAGE_3_CARRY_3;
    ///
    /// let cks = ClientKey::new(PARAM_MESSAGE_3_CARRY_3);
    ///
    /// let msg = 27_u64;
    /// let basis: Vec<u64> = vec![2, 3, 5];
    /// // Encryption of one message:
    /// let mut ct = cks.encrypt_crt_not_power_of_two(msg, basis);
    ///
    /// // Decryption:
    /// let dec = cks.decrypt_crt_not_power_of_two(&ct);
    /// assert_eq!(msg, dec);
    /// ```
    pub fn decrypt_crt_not_power_of_two(&self, ct: &CrtCiphertext) -> u64 {
        let mut val: Vec<u64> = vec![];

        //Decrypting each block individually
        for (c_i, b_i) in ct.blocks.iter().zip(ct.moduli.iter()) {
            //decrypt the component i of the integer and multiply it by the radix product
            val.push(
                self.key
                    .decrypt_message_and_carry_not_power_of_two(c_i, *b_i as u8),
            );
        }

        //Computing the inverse CRT to recompose the message
        let result = i_crt(&ct.moduli, &val);

        let whole_modulus: u64 = ct.moduli.iter().copied().product();

        result % whole_modulus
    }
}
