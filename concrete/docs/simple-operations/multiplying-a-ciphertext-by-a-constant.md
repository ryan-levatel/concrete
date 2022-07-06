# Multiplying a ciphertext by a constant

Multiplying a ciphertext by a constant means multiplying a ciphertext by a constant \(plaintext value\). This is a leveled operation that increases noise, optionally consume padding, and optionally changes the encoding.

|  |  |
| :--- | :--- |
| Operation | $$E[m_1] * m_2 = E[m_1 * m_2]$$ |
| Type | Leveled |
| Side effects | <p>Increases noise</p><p>Potentially consumes padding</p><p>Potentially modifies encoding</p> |

## Multiplying an LWE by a integer constant

By default, LWE ciphertexts can only be multiplied by integer constants. Under the hood, this is done by multiplying the ciphertext's body and mask by the constant. This is only currently implemented statically, i.e. without modifying the encoder, via the `mul_constant_static_encoder` method \(and its mutable form `mul_constant_static_encoder_inplace`\).

{% hint style="danger" %}
Because integer constant addition is implemented using a static encoder, the result of the multiplication should be in the interval of the ciphertext's encoder to avoid wrapping around with undefined behavior.
{% endhint %}

Here is an example using the mutable form:

```rust
/// file: main.rs
use concrete::*;

fn main() -> Result<(), CryptoAPIError> {
    // encoder
    let encoder = Encoder::new(-30., 30., 8, 0)?;

    // generate a secret key
    let secret_key = LWESecretKey::new(&LWE128_1024);

    // encrypt the message
    let message: f64 = 6.2;
    let mut ciphertext = LWE::encode_encrypt(&secret_key, message, &encoder)?;
    // multiply in place by an integer constant
    let constant: i32 = -4;
    ciphertext.mul_constant_static_encoder_inplace(constant)?;

    // decrypt
    let output: f64 = ciphertext.decrypt_decode(&secret_key)?;

    println!("{} * {} = {}", message, constant, output);
    Ok(())
}
```

This operation is also available in vectorized form for `VectorLWE` instances, simply by passing a vector of integers to the `mul_constant_static_encoder` method:

```rust
// encode and encrypt
let messages: Vec<f64> = vec![6.1, 5.4, -2.7];
let mut ciphertext_vector = VectorLWE::encode_encrypt(&secret_key, &messages, &encoder)?;

// vector multiplication between ciphertext and constants
let constants: Vec<i32> = vec![-4, 5, 3];
ciphertext_vector.mul_constant_static_encoder_inplace(&constants)?;

// decryption
let outputs: Vec<f64> = ciphertext_vector.decrypt_decode(&secret_key)?;
```

## Multiplying an LWE by a real constant

Multiplying a ciphertext by a real-valued constant is supported in Concrete thanks to the use of padding in the encoder, via the `mul_constant_with_padding` method \(and its mutable counterpart `mul_constant_with_padding_inplace`\). The method take 3 arguments:

* `constant`: the constant to multiply the ciphertext by, as a float64
* `max_constant`: the maximum value the constant can take. This is necessary to determine the encoding of the result of the multiplication, and particularly useful when multiplying several ciphertexts by different constants \(for example when working with `VectorLWE`\), as the output encoding of the ciphertexts will end up being the same.
* `nb_bit_padding`: the number of bits of padding to be consumed by the multiplication, which also represents the precision of the constant being multiplied. This cannot be bigger than the remaining bits of padding in the ciphertext being multiplied.

Here is an example code:

```rust
use concrete::*;

fn main() -> Result<(), CryptoAPIError> {
    // encoder
    let encoder = Encoder::new(-10., 10., 10, 4)?;

    // generate a secret key
    let secret_key = LWESecretKey::new(&LWE128_1024);

    // encrypt the message
    let message: f64 = 4.;
    let mut ciphertext = LWE::encode_encrypt(&secret_key, message, &encoder)?;

    // multiply in place by a 4-bit real constant
    let constant: f64 = 2.5;
    let max_constant: f64 = 3.;
    let nb_bit_padding = 4;
    ciphertext.mul_constant_with_padding_inplace(constant, max_constant, nb_bit_padding)?;

    // decrypt
    let output: f64 = ciphertext.decrypt_decode(&secret_key)?;

    println!("{} * {} = {}", message, constant, output);
    Ok(())
}
```

And in vectorized form, where all ciphertexts end up with the same encoder interval:

```rust
// encode and encrypt
let messages: Vec<f64> = vec![6.1, 5.4, -2.7];
let mut ciphertext_vector = VectorLWE::encode_encrypt(&secret_key, &messages, &encoder)?;

// vector multiplication between ciphertext and constants
let constants: Vec<f64> = vec![-2.1, 1.4, 3.2];
let max_constant: f64 = 4.;
let nb_bit_padding = 4;
ciphertext_vector.mul_constant_with_padding_inplace(&constants, max_constant, nb_bit_padding)?;

// decryption
let outputs: Vec<f64> = ciphertext_vector.decrypt_decode(&secret_key)?;
```

