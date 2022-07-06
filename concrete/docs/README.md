# Getting started

**Concrete** is a [fully homomorphic encryption \(FHE\)](https://en.wikipedia.org/wiki/Homomorphic_encryption) library that implements Zama's variant of [TFHE](https://eprint.iacr.org/2018/421.pdf). TFHE is based on [Learning With Errors \(LWE\)](https://en.wikipedia.org/wiki/Learning_with_errors), a well studied cryptographic primitive believed to be secure even against quantum computers.

{% hint style="warning" %}
Concrete is currently released in alpha. The API is not stable and likely to change short term.
{% endhint %}

{% hint style="info" %}
Concrete is an open source library. The code is available on [Github](https://github.com/zama-ai/concrete).
{% endhint %}

In cryptography, a raw value is called a **message** \(also sometimes called a **cleartext**\), an encoded message is called a **plaintext** and an encrypted plaintext is called a **ciphertext**.

The idea of homomorphic encryption is that you can compute on ciphertexts while not knowing messages encrypted in them. A scheme is said to be _fully homomorphic_, meaning any program can be evaluated with it, if at least two of the following operations are supported \($$x$$is a plaintext and $$E[x]$$ is the corresponding ciphertext\):

* homomorphic univariate function evaluation: $$f(E[x]) = E[f(x)]$$
* homomorphic addition: $$E[x] + E[y] = E[x + y]$$
* homomorphic multiplication: $$E[x] * E[y] = E[x * y]$$

Zama's variant of TFHE is fully homomorphic and deals with approximate real numbers \($$\mathbb{R}$$\) as messages. It implements homomorphic addition and function evaluation via **Programmable Bootstrapping**. You can read more about Zama's TFHE variant in the [preliminary whitepaper](https://whitepaper.zama.ai/).

Using FHE in a Rust program with Concrete consists in:

* generating a secret key using secure parameters
* encoding input messages into fixed-precision plaintexts
* encrypting plaintexts using the secret key to produce ciphertexts
* operating homomorphically on ciphertexts
* decrypting the resulting ciphertexts into plaintexts using the secret key
* decoding plaintexts to get the final output messages

Here is an example program that adds two ciphertexts:

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
    let m3 = c1.decrypt_decode(&secret_key)?;

    // print the result and compare to non-FHE addition
    println!("Real: {}, FHE: {}", m1 + m2, m3);

    Ok(())
}
```

{% hint style="info" %}
Concrete being a library, all functions are wrapped in a `Result` to let you manage errors the way you see fit for your program.
{% endhint %}

This guide will walk you through using the Concrete library to build homomorphic programs, explaining the underlying key concepts as they are encountered.

