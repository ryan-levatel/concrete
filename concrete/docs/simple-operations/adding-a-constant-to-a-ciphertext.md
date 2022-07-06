# Adding a constant to a ciphertext

Adding a constant to an LWE ciphertext is a leveled operation that does not increase noise and does not consume padding, but can optionally change the interval of the encoder, depending on the method being used.

|  |  |
| :--- | :--- |
| Operation | $$E[m_1] + m_2 = E[m_1 + m_2]$$ |
| Type | Leveled |
| Side effects | Potentially modifies encoding |

## Adding a constant to an LWE

There are two ways to add a constant to a ciphertext:

* using the `add` method which adds a constant $$m$$ to a ciphertext and shift the interval of the encoder by that constant, thus going from an interval of $$[min, max[$$ to an interval of $$[min+m, max+m[$$. Note that with this method, the ciphertext itself is not modified, as we only need to change the encoding to get the correct value. This is a convenience alias of the `add_constant_dynamic_encoder` method.
* using the `add_constant_static_encoder` method that adds a constant to a ciphertext without changing the encoding. With this method, the ciphertext itself is changed by adding the constant to its body, while the encoding remains the same.

Both methods also exist in mutable form that modify the current ciphertext: `add_inplace` \(or its verbose form `add_constant_dynamic_encoder_inplace`\) and `add_constant_static_encoder_inplace`.

{% hint style="info" %}
The value of the constant being added in the dynamic method does not have to be in the interval of the original encoder.
{% endhint %}

{% hint style="danger" %}
If the result of adding a constant to a ciphertext using the static method ends up outside the interval of the original ciphertext, the result will wrap around the interval with undefined behavior.
{% endhint %}

The example below shows how to add a constant to an LWE:

```rust
/// file: main.rs
use concrete::*;

fn main() -> Result<(), CryptoAPIError> {
    // generate a secret key
    let secret_key = LWESecretKey::new(&LWE128_1024);
    // encoder
    let encoder = Encoder::new(100., 210., 8, 0)?;

    // encode and encrypt
    let message = 106.276;
    let mut ciphertext = LWE::encode_encrypt(&secret_key, message, &encoder)?;

    // addition between ciphertext and a constant
    let constant = 102.0;
    ciphertext.add_constant_static_encoder_inplace(constant)?;
    
    // decryption
    let output = ciphertext.decrypt_decode(&secret_key)?;
    println!("{} + {} = {}", message, constant, output);
    Ok(())
}
```

## Adding a vector of constant to a VectorLWE

Both dynamic and static methods, as well as their mutable counterparts, exist in vectorized form when operating with a `VectorLWE` struct. In this case, constants in the vector are added element wise to the vector of ciphertexts:

```rust
// encode and encrypt
let messages: Vec<f64> = vec![106.276, 104.3, 100.12, 101.1, 107.78];
let mut ciphertext_vector = VectorLWE::encode_encrypt(&secret_key, &messages, &encoder)?;

// addition between ciphertexts and constants
let constants: Vec<f64> = vec![-4.9, 1.02, 4.6, 5.6, -3.2];
ciphertext_vector.add_constant_dynamic_encoder_inplace(&constants)?;

// decryption
let outputs: Vec<f64> = ciphertext_vector.decrypt_decode(&secret_key)?;
```

