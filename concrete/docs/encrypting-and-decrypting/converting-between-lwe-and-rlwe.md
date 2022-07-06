# Understanding RLWE

While you do not need to fully understand RLWE to use Concrete, it is useful to know they exist, as they will be used under the hood to perform **bootstrapping** \(which we will learn about later\).

RLWE stands for [Ring Learning With Errors](https://eprint.iacr.org/2012/230.pdf) and refers to the extension of LWE over the ring of polynomials with coefficients in a modular integer ring. It is also a computational problem conjectured to be hard to solve. RLWE enable packing multiple ciphertexts into a single polynomial, enabling SIMD-like homomorphic operations.

{% hint style="info" %}
Concrete implements RLWE and VectorRLWE structs, but without the ability to perform SIMD-like operations on them. This will be available in a future release.
{% endhint %}

## Extracting an RLWE coefficient as an LWE

Since RLWE is an extension of LWE,  you can extract one of the RLWE ciphertext polynomial coefficient as an LWE ciphertext.

RLWE instances are 2-dimensional: they hold a vector of ciphertexts, in which each coefficient is itself a plaintext. Thus, when extracting an LWE, we need to both specify the coefficient we want as well as the ciphertext from which to extract that coefficient. This is done via the `extract_1_lwe` function:

```rust
// extracting the 3rd coefficient from the 1st ciphertext
// ciphertexts and coefficients are zero-indexed
let lwe_ciphertext: VectorLWE = rlwe_ciphertext.extract_1_lwe(2, 0)?;
```

## Converting an RLWE secret key into an LWE secret key

Converting an `RLWESecretKey` instance into an `LWESecretKey` is done using `to_lwe_secret_key` function:

```rust
// convert the RLWE secret key into an LWE secret key
let lwe_sk = rlwe_sk.to_lwe_secret_key();
```

## Converting an LWE secret key into an RLWE secret key

Sometimes, you might need to do the opposite operation, and convert an LWE secret key into an RLWE secret key. This works almost the same, the only difference being that you have to specify the polynomial size when you use the `to_rlwe_secret_key` method:  This assumes that the LWE dimension is a multiple of $$N$$ \(i.e,, the degree of the polynomial\).

```rust
// convert the LWE secret key into an RLWE secret key
let rlwe_sk = lwe_sk.to_rlwe_secret_key(512)?;
```

