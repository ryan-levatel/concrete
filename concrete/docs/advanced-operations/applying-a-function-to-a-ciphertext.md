# Applying a function to a ciphertext

**Programmable bootstrapping** is a powerful technique that enables simultaneously bootstrapping a ciphertext and homomorphically evaluating a function on it. Without programmable bootstrapping, evaluating complex non-linear functions would require evaluating deep arithmetic or boolean circuits, with as many bootstraps as there is noise accumulation. Here, the same function can be evaluated for the cost of a single bootstrap.

| Operation | $$f(E[m]_{noisy}) \rightarrow E[f(m)]_{clean}$$ |
| :--- | :--- |
| Type | Bootstrapped |
| Side effects | <p>Reduces noise</p><p>Modifies padding</p><p>Potentially modifies encryption key</p><p>Potentially modifies security parameters</p> |

## Discretizing the function to be evaluated

A simple way to think of programmable bootstrapping is as a homomorphic table lookup, where the table represents a discretization of the function $$f$$ that needs to be evaluated on the ciphertext.

{% hint style="info" %}
In TFHE, and thus Zama, we can bootstrap using polynomials modulo $$X^N+1$$, and get as an intermediary step an encryption of a polynomial whose constant term is the input plaintext. Programming the bootstrapping operation then amounts to simply replacing this constant term by a table representing the discretized function being programmed. This table has to be provided with entries of the form $$\bigl(\operatorname{encode}_{\mathrm{in}}(m),\operatorname{encode}_{\mathrm{out}}(f(m))\bigr)$$ with $$\operatorname{encode}_{\mathrm{in}}()$$denotes the encoding function of the input and $$\operatorname{encode}_{\mathrm{out}}()$$ the encoding function of the output.
{% endhint %}

{% hint style="warning" %}
Just with plain bootstrapping, choosing the right parameters is paramount to get the right tradeoff between performances and precision.
{% endhint %}

{% hint style="danger" %}
Just as with plain bootstrapping, programmable bootstrapping requires at least one free bit of padding.
{% endhint %}

## Applying a function on the ciphertext

To apply a function on a ciphertext, use the `bootstrap_with_function` method that takes as arguments:

* a **bootstrapping key**.
* the **function to be evaluated**, as a lambda `Fn(f64) -> f64` , which can be any univariate function as long as it does not have side effects.
* an **output encoder** that represents the range and precision of the resulting ciphertext, after the function has been applied to it.

Here is a code example to evaluate the square function:

```rust
use concrete::*;

fn main() -> Result<(), CryptoAPIError> {
    // encoders
    let encoder_input = Encoder::new(-10., 10., 6, 1)?;
    let encoder_output = Encoder::new(0., 100., 6, 0)?;

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
    let c2 = c1.bootstrap_with_function(&bsk, |x| x * x, &encoder_output)?;

    // decrypt
    let output = c2.decrypt_decode(&sk_out)?;

    println!("before bootstrap: {}, after bootstrap: {}", message, output);

    Ok(())
}

```

~~~~

