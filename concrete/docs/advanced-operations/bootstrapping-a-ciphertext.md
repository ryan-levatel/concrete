# Bootstrapping a ciphertext

The issue with manipulating noisy ciphertexts in FHE is that each leveled operation will increase the noise, eventually overflowing on the significant data bits and rendering the resulting computing imprecise. To avoid this from happening and carry on computing forever, ciphertexts need to be "cleaned up" whenever the noise grows too big, using a special procedure called **bootstrapping**.

| Operation | $$E[m]_{noisy} \rightarrow E[m]_{clean}$$ |
| :--- | :--- |
| Type | Bootstrapped |
| Side effects | <p>Reduces noise</p><p>Modifies padding</p><p>Potentially modifies encryption key</p><p>Potentially modifies security parameters</p> |

The original intuition behind bootstrapping \(as introduced by [Gentry](https://www.cs.cmu.edu/~odonnell/hits09/gentry-homomorphic-encryption.pdf)\) is that by homomorphically evaluating the decryption circuit, we can reset the noise in the ciphertext to a nominal level. This requires a public **bootstrapping key** $$bsk$$, which is an encryption under a key $$s_{out}$$ of the secret key $$s_{in}$$ used to encrypt the input ciphertext.

The bootstrapping operation thus works by taking as input a noisy ciphertext encrypted under some secret key $$s_{\mathrm{in}}$$ and a bootstrapping key $$bsk$$, producing a refreshed ciphertext \(i.e., with a reduced amount of noise\), encrypted under the secret key $$s_{\mathrm{out}}$$. A key-switch can then be performed to obtain a ciphertext encrypted under the original $$s_{\mathrm{in}}$$.

## Generating a bootstrapping key

A bootstrapping key is a list of **RGSW ciphertexts**, which are themselves a collection of RLWE ciphertexts. Each RGSW ciphertext composing the bootstrapping key encrypts a bit of the secret key $$s_{\mathrm{in}}$$used to encrypt the input ciphertext. This explains why two keys are needed in the generation of a bootstrapping key: the input LWE secret key $$s_{\mathrm{in}}$$and a RLWE secret key to produce the RGSW ciphertexts of the bits composing $$s_{\mathrm{in}}$$.

The generation of a bootstrapping key involves three parameters, a basis `base_log` , a number of levels `level` , and a polynomial size $$N$$.  The choice of these parameters is important as they affect the amount of noise and precision of the output ciphertext, as well as the computational cost of performing a bootstrap. They also determine the size of the bootstrapping key. For example, the parameter $$N$$relates to the discretization used for the bootstrapping, which in turn impacts the output precision. A larger value for $$N$$increases the output precision but it also increases the bootstrapping time. Thus, finding a set of parameters offering good performance trade-offs is essential.

For example, for an LWE ciphertext with dimension `n = 1024`,  setting the bootstrapping parameters to `N = 1024` , `level=4` and `base_log=6` will guarantee 3 bits of precision in the output ciphertext, and 4 bits with a probability of 97%.

{% hint style="info" %}
As a rule of thumb, it is good to try keeping a small value for `level`. Generally, a good choice for parameter$$N$$is 1024 or any  other higher power of two.
{% endhint %}

{% hint style="warning" %}
Bootstrapping keys can be several hundreds of megabytes large and take several minutes to generate using OpenSSL's secure pseudo-random number generator. During development, Rust's faster, but unsafe prng can be used by specifying the cargo flag "--features=unsafe" \(never use this in production!\).
{% endhint %}

Here is an example of how to generate a bootstrapping key:

```rust
use concrete::*;

fn main() -> Result<(), CryptoAPIError> {

    // settings
    let base_log: usize = 5;
    let level: usize = 3;

    // secret keys
    let sk_rlwe = RLWESecretKey::new(&RLWE128_1024_1);
    let sk_in = LWESecretKey::new(&LWE128_630);
    let sk_out = sk_rlwe.to_lwe_secret_key();

    // bootstrapping key
    let bsk = LWEBSK::new(&sk_in, &sk_rlwe, base_log, level);

    // save the key to avoid regenerating it each time
    bsk.save("my_bootstrapping_key.json");

    // load it in memory
    let loaded_bsk = LWEBSK::load("my_bootstrapping_key.json");


    Ok(())
}
```

## Bootstrapping a ciphertext

Bootstrapping a ciphertext is done using the `bootstrap` method, which takes the bootstrapping key as input. Although bootstrapping can free up padding, it will first need to consume one bit of padding.

{% hint style="danger" %}
There must be at least one available bit of padding in the input ciphertext to perform a bootstrapping operation on it.
{% endhint %}

```rust
use concrete::*;

fn main() -> Result<(), CryptoAPIError> {
    // encoders
    let encoder_input = Encoder::new(-10., 10., 6, 1)?;
    let encoder_output = Encoder::new(0., 101., 6, 0)?;

    // secret keys
    let sk_rlwe = RLWESecretKey::new(&RLWE128_1024_1);
    let sk_in = LWESecretKey::new(&LWE128_630);
    let sk_out = sk_rlwe.to_lwe_secret_key();

    // bootstrapping key
    let bsk = LWEBSK::new(&sk_in, &sk_rlwe, 5, 3);

    // messages
    let message: f64 = -5.;

    // encode and encrypt
    let c1 = LWE::encode_encrypt(&sk_in, message, &encoder_input)?;

    // bootstrap
    let c2 = c1.bootstrap(&bsk)?;

    // decrypt
    let output = c2.decrypt_decode(&sk_out)?;

    println!("before bootstrap: {}, after bootstrap: {}", message, output);

    Ok(())
}
```

