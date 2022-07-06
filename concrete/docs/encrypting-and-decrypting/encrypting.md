# Encrypting with LWE

The simplest way of encrypting plaintexts into ciphertexts in Concrete is via **LWE** encryption.

LWE stands for [Learning With Errors](https://cims.nyu.edu/~regev/papers/lwesurvey.pdf) and refers to a computational problem conjectured to be hard to solve. With LWE, every computation is performed in a modular integer ring such as $$\mathbb{Z}/q\mathbb{Z}$$ where $$q$$ is the modulus \(typically 64\).

{% hint style="info" %}
For simplicity, we use "LWE" and "LWE ciphertext" interchangeably.
{% endhint %}

## Choosing strong security parameters

An LWE is composed of a vector of integers called a **mask** and an integer called a **body.** The size of the mask vector is called the **dimension.** To achieve a strong level of security, we need to add random gaussian noise to the body. The combination of the mask's dimension and standard deviation of the noise distribution is what we call the **LWE security parameters.** 

{% hint style="danger" %}
Choosing wrong security parameters can lead to weak security, slow computations or insufficient precision to carry the computations.
{% endhint %}

Parameters are stored in a `LWEParams` struct that takes the dimension and standard deviation as parameters. Concrete also comes with predefined sets of parameters for 80 or 128 bits of security. These parameters were secure as of **September 15th 2020**, and estimated using the [LWE estimator](https://bitbucket.org/malb/lwe-estimator/src/master/).

```rust
// manually chosen parameters for 80 and 128 bits of security
let lwe80 = LWEParams::new(256, -19);
let lwe128 = LWEParams::new(630, -14);

// Predefined consts with parameters for 80 bits of security:
LWE80_256;  // dimension = 256,  noise = 2^-9
LWE80_512;  // dimension = 512,  noise = 2^-19
LWE80_630;  // dimension = 630,  noise = 2^-24
LWE80_650;  // dimension = 650,  noise = 2^-25
LWE80_688;  // dimension = 690,  noise = 2^-26
LWE80_1024; // dimension = 1024, noise = 2^-30

// Predefined consts with parameters for 128 bits of security:
LWE128_256;  // dimension = 256,  noise = 2^-5
LWE128_512;  // dimension = 512,  noise = 2^-11
LWE128_630;  // dimension = 630,  noise = 2^-14
LWE128_650;  // dimension = 650,  noise = 2^-15
LWE128_688;  // dimension = 690,  noise = 2^-16
LWE128_1024; // dimension = 1024, noise = 2^-25
```

We can see above that for a given security level, **the larger the dimension is, the smaller the noise standard deviation has to be**. A larger dimension will lead to more computation and larger ciphertexts, while a larger standard deviation will lead to more noisy ciphertexts and less precise messages. Hence, there is a tradeoff between performance and precision, which is inherent to any FHE program.

{% hint style="info" %}
A good rule of thumb is to pick secure parameters with the largest possible noise that supports your program's desired precision. By not provisioning unnecessary precision, you can use a smaller mask dimension and thus get better runtime performance. 
{% endhint %}

## Generating an LWE secret key

Once appropriate security parameters have been chosen, we can generate a secret key that will be used to encrypt and decrypt ciphertexts. Concrete currently only implements symmetric uniformly random binary secret keys. Future versions will offer support for public-key cryptography and other key generation methods.

Creating a secret key in Concrete is as easy as using the `new` function from the `LWESecretKey` struct, and passing it the chosen security parameters:

```rust
// pick a set of LWE parameters
let lwe_params = LWE128_630;

// generate a fresh secret key
let secret_key = LWESecretKey::new(&lwe_params);
```

Secret keys can be saved into json files with the `save` method, and recovered using the `load` method:

```rust
// save secret key
secret_key.save("my_very_secret_key.json").unwrap();


// load secret key
let recovered_secret_key = LWESecretKey::load("my_very_secret_key.json").unwrap();
```

## Encrypting messages

Encrypting messages can be done by either:

* using the `LWE` struct's factory method `encrypt`, which takes a plaintext and a secret key as a parameter.
* using the `LWE` struct's factory method `encode_encrypt`, which takes a message, an encoder and a secret key. This method will encode the messages before encrypting them.

The following code shows how to create an LWE by encoding and encrypting in one step:

```rust
// generate a secret key
let secret_key = LWESecretKey::new(&LWE128_630);

// encoder
let encoder = Encoder::new(-10., 10., 8, 0)?;

// message to encrypt
let message: f64 = -6.276;

// encode and encrypt the message in one step
let c1 = LWE::encode_encrypt(&secret_key, message, &encoder)?;
```

In FHE, it is often necessary to manipulate a vector of encrypted values, rather than a single value. Concrete has a convenience struct to simplify working with vectors of LWEs called `VectorLWE`, which has the same methods as the LWE struct, but taking a vector of message as input:

```rust
// a vector of messages
let messages: Vec<f64> = vec![-6.276, 4.3, 0.12, -1.1, 7.78];

// encode and encrypt a vector of messages into a single VectorLWE
let c2 = VectorLWE::encode_encrypt(&secret_key, &messages, &encoder)?;
```

## Decrypting ciphertexts

Decryption turns a ciphertext into a plaintext and decodes it to yield the final message. The same secret key that was used for encryption must be used for decryption. The `decrypt_decode` method exists both for LWE and VectorLWE ciphertexts:

```rust
// decrypt an LWE into a single value
let o1: f64 = c1.decrypt_decode(&secret_key)?;

// decrypt a VectorLWE into a vector of values
let o2: Vec<f64> = c2.decrypt_decode(&secret_key)?;
```

The `decrypt_decode` method performs two separate operations:

* the **decryption**, which decrypts the ciphertext using the secret key
* the **decoding**, which removes the noise and decodes the result back to the domain of the original message.

## Putting everything together

Here is a complete example using a vector of messages:

```rust
/// file: main.rs
use concrete::*;

fn main() -> Result<(), CryptoAPIError> {
    // generate a secret key and save it
    let secret_key = LWESecretKey::new(&LWE128_630);
    secret_key.save("my_very_secret_key.json");

    // create an encoder
    let encoder = Encoder::new(-10., 10., 8, 0)?;

    // a list of messages
    let messages: Vec<f64> = vec![-6.276, 4.3, 0.12, -1.1, 7.78];

    // encode and encrypt message vector
    let ciphertext = VectorLWE::encode_encrypt(&secret_key, &messages, &encoder)?;

    // decrypt
    let outputs: Vec<f64> = ciphertext.decrypt_decode(&secret_key)?;

    println!("{:?}", outputs);
    Ok(())
}
```

