# Negating a ciphertext

Negating a value means taking its **opposite**. The opposite of a ciphertext representing a message$$m$$ in the interval $$[min, max]$$ is a ciphertext representing $$-m$$ in the interval $$[-max, -min]$$. This operation does not consume padding nor add noise but it modifies the interval of the encoder.

|  |  |
| :--- | :--- |
| Operation | $$opposite(E[m]) = E[-m]$$ |
| Type | Noiseless |
| Side effects | Modifies encoding |

## Computing an LWE opposite

To compute the opposite of an LWE, simply use the `opposite` method, which will return a new ciphertext with the modified value. The method exists in a mutable `opposite_inplace` form as well, which modifies the ciphertext itself. All operations in concrete are implemented in immutable and mutable forms, with mutable forms always postfixed with `_inplace`.

Here is a complete example for a single LWE:

```rust
/// file: main.rs
use concrete::*;

fn main() -> Result<(), CryptoAPIError> {
    // encoder
    let encoder = Encoder::new(50., 100., 8, 2)?;

    // generate a secret key
    let secret_key = LWESecretKey::new(&LWE128_1024);

    // the message to negate
    let message: f64 = 95.46;

    // encode and encrypt
    let mut ciphertext = LWE::encode_encrypt(&secret_key, message, &encoder)?;

    // compute the opposite of the ciphertext
    ciphertext.opposite_inplace()?;

    // decryption
    let output: f64 = ciphertext.decrypt_decode(&secret_key)?;

    // check the value computed
    println!("opposite({}) = {}", message, output);
    Ok(())
}
```

As for all operations in Concrete, they can be applied to a vector of messages using the `VectorLWE` struct instead of `LWE`. The vectorized form has an additional method `opposite_nth` that enables negating a single value by passing its index to the function.

