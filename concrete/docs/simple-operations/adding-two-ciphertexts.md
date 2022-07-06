# Adding and subtracting ciphertexts

Adding or subtracting LWE ciphertexts together is a leveled operation that increases noise and potentially consumer padding and modify the encoding. It is one of the fundamental FHE operation.

| Operation | $$E[m_1] \pm E[m_2] = E[m_1 \pm m_2]$$ |
| :--- | :--- |
| Type | Leveled |
| Side effects | <p>Increases noise</p><p>Potentially consumes padding</p><p>Potentially modifies encoding</p> |

## Adding LWE ciphertexts

The common way to add ciphertexts is to consume bits of padding and update the interval of their respective encoders. This can be achieved using the short form method `add` \(or `add_inplace`\) which simply takes another ciphertext as argument. This is an alias for the more verbose `add_with_padding` \(or `add_with_padding_inplace`\).

The constraint however is that the ciphertexts need to be encoded in the same interval and with the same number of padding bits. The result of adding $$c_1$$ and $$c_2$$ will be encoded in the interval $$[min_1 + min_2, max_1 + max_2[$$ with one less bit of padding.

{% hint style="info" %}
Homomorphic subtraction works exactly the same as addition, using the `sub_with_padding` \(or `sub_with_padding_inplace`\) methods.
{% endhint %}

Here is a code example:

```rust
use concrete::*;

fn main() -> Result<(), CryptoAPIError> {
    // generate a secret key
    let secret_key = LWESecretKey::new(&LWE128_630);

    // the two values to add
    let m1 = 8.2;
    let m2 = 5.6;

    // Encode in [0, 10[ with 8 bits of precision and 1 bit of padding
    let encoder = Encoder::new(0., 10., 8, 1)?;

    // encrypt plaintexts
    let mut c1 = LWE::encode_encrypt(&secret_key, m1, &encoder)?;
    let c2 = LWE::encode_encrypt(&secret_key, m2, &encoder)?;

    // add the two ciphertexts homomorphically, and store in c1
    c1.add_with_padding_inplace(&c2)?;

    // decrypt and decode the result
    let m3: f64 = c1.decrypt_decode(&secret_key)?;
    // print the result and compare to non-FHE addition
    println!("Real: {}, FHE: {}", m1 + m2, m3);
    Ok(())
}
```

And in vectorized form:

```rust
// message vectors to add
let mv1: Vec<f64> = vec![1.2, 4.3, 0.11, 3.1, 6.7];
let mv2: Vec<f64> = vec![7.0, 1.0, 8.2, 3.7, 9.4];

// Encode in [0, 10[ with 8 bits of precision and 1 bit of padding
let encoder = Encoder::new(0., 10., 8, 1)?;

// encode encrypt
let mut cv1 = VectorLWE::encode_encrypt(&secret_key, &mv1, &encoder)?;
let cv2 = VectorLWE::encode_encrypt(&secret_key, &mv2, &encoder)?;

// add ciphertext vectors element-wise
cv1.add_with_padding_inplace(&cv2)?;
```

## Adding LWE ciphertexts without consuming padding

If the interval of the output of the homomorphic addition is known, it is possible to add ciphertexts without consuming padding. To do so, you can use the `add_with_new_min` \(or `add_with_new_min_inplace`\) method that takes as arguments the ciphertext to add and the minimum `new_min` of the interval of the result.

There are constraints when using this method, namely that the ciphertexts must be encoded in intervals of the same size, meaning $$max_1 - min_1 = max_2 - min_2$$ and have the same precision. The interval of the output ciphertext will then be $$[new\_min, new\_min + (max_1 - min_1)]$$ .

{% hint style="danger" %}
If the result of the homomorphic addition is outside of the specified range, the behavior is undefined and the result most likely to be incorrect.
{% endhint %}

{% hint style="info" %}
Subtracting ciphertexts without consuming padding is not yet implemented in Concrete.
{% endhint %}

Here is a code example:

```rust
use concrete::*;

fn main() -> Result<(), CryptoAPIError> {
    // generate a secret key
    let secret_key = LWESecretKey::new(&LWE128_630);

    // the two values to add
    let m1 = 8.;
    let m2 = 9.;

    // Encode in [0, 10[ with 8 bits of precision and 1 bit of padding
    let encoder = Encoder::new(0., 10., 8, 1)?;

    // encrypt plaintexts
    let mut c1 = LWE::encode_encrypt(&secret_key, m1, &encoder)?;
    let c2 = LWE::encode_encrypt(&secret_key, m2, &encoder)?;

    // add the two ciphertexts homomorphically
    let new_min = 10.;
    c1.add_with_new_min_inplace(&c2, new_min)?;

    // decrypt and decode the result
    let m3: f64 = c1.decrypt_decode(&secret_key)?;

    // print the result and compare to non-FHE addition
    println!("Real: {}, FHE: {}", m1 + m2, m3);
    Ok(())
}
```

