# Key-switching

The **key-switching** allows to convert a ciphertext encrypted with a secret key, to a ciphertext encrypted with another secret key. This requires a special Key-switching key \($$ksk$$\). Key-switching is used primarily to change the dimension security parameter of a ciphertext, and as part of the bootstrapping procedure.

| Operation | $$E_{k_1}[m] \rightarrow E_{k_2} [m]$$ |
| :--- | :--- |
| Type | Leveled |
| Side effects | <p>Modifies encryption key</p><p>Potentially modifies security parameters</p> |


## Generating a key-switching key

A Key-switching key $$ksk$$ is an encryption of the bits of the original secret key \(`secret_key_before`\) under the destination secret key \(`secret_key_after`\). To generate a key-switching key, you can use the structure `LWEKSK` with the following parameters:

* `secret_key_before`: the key under which the ciphertext is encrypted
* `secret_key_after`: the key under which we want the ciphertext to be encrypted after the key-switch
* `base_log`: number of bits of the decomposition base
* `level`: precision of the decomposition

Both the `base_log` and the `level` parameters are used to managed the noise of the ciphertext and the message precision on the plaintext. They also impact directly the computation cost and the key-switching key size. The `level` is usually chosen small to obtain a good tradeoff between all parameters.

Here is a code example:

```rust
/// file: main.rs
use concrete::*;

fn main() {
    // generate two secret keys
    let secret_key_before = LWESecretKey::new(&LWE128_1024);
    let secret_key_after = LWESecretKey::new(&LWE128_630);

    // generate the key switching key
    let ksk = LWEKSK::new(&secret_key_before, &secret_key_after, 8, 3);

    println!("Well done :-)");
}
```

## Performing a key-switch

Performing a key-switch is done by calling the method `keyswitch` , which takes a key-switching key as input, and outputs a ciphertext under the new key. Note that in this example, the ciphertext also changes the dimension security parameter, from 1024 to 630.

```rust
/// file: main.rs
use concrete::*;

fn main() -> Result<(), CryptoAPIError> {
    // encoder
    let encoder = Encoder::new(100., 110., 5, 0)?;

    // generate two secret keys
    let secret_key_before = LWESecretKey::new(&LWE128_1024);
    let secret_key_after = LWESecretKey::new(&LWE128_630);

    // generate the key switching key
    let ksk = crypto_api::LWEKSK::new(&secret_key_before, &secret_key_after, 2, 6);

    // a list of messages that we encrypt
    let messages: Vec<f64> = vec![106.276, 104.3, 100.12, 101.1, 107.78];
    let ciphertext_before = VectorLWE::encode_encrypt(&secret_key_before, &messages, &encoder)?;

    // key switch
    let ciphertext_after = ciphertext_before.keyswitch(&ksk);

    // decryption
    let decryptions: Vec<f64> = ciphertext_before.decrypt_decode(&secret_key_before)?;

    Ok(())
}
```

