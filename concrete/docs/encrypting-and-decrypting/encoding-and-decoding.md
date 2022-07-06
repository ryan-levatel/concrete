# Encoding messages

Concrete enables operating homomorphically on real-values by **encoding** them into fixed-precision representation called **plaintexts**. Encoders have:

* an **interval** $$[min, max] \subset \mathbb{R}$$ to work in, with **size** equal to $$max-min$$ .
* a **precision** $$n$$ in bits, representing the **granularity** of the interval. The granularity is the smallest increment between two consecutive values, and is equal to$$\frac{max-min}{2^n}$$ .

Defining the right encoders is important to ensure your homomorphic program runs accurately and efficiently. More precision typically means more internal operations, and thus, a more computationally expensive homomorphic program, while less precision can lead to imprecise results.

{% hint style="info" %}
Always chose the smallest possible precision that yields the desired output. This will ensure your homomorphic program runs faster!
{% endhint %}

## Creating an encoder

Concrete simplifies managing precision by providing an `Encoder` struct that encodes real messages into plaintexts. An encoder takes three parameters:

* an interval $$[min, max]$$ representing the range of values your messages can take
* the number of bits of precision needed to represent your data
* the number of bits of padding to carry on leveled operations \(more on that later\)

Here is an example encoder that can represent messages in $$[-10, 10]$$ with 8 bits of precision and 0 bits of padding:

```rust
let min = -10.;
let max = 10.;
let precision = 8; // bits
let padding = 0;   // bits

// create an Encoder instance
let encoder = Encoder::new(min, max, precision, padding)?;
```

Instead of using the min and max of the interval, an encoder can also be defined using the center value of the interval and a radius:

```rust
let center = 0.;
let radius = 10.;
let precision = 8;
let padding = 0;

// this is equivalent to the previous encoder
let encoder = Encoder::new_centered(center, radius, precision, padding)?;
```

Using the above encoders, $$2^8 = 256$$ values can be represented, with $$-10$$ being the smallest value, $$10$$ being the largest, and a granularity of $$\frac{max-min}{2^8} = 0.078125$$ between consecutive values. The granularity of an encoder can be computed with its `get_granularity` method.

Concrete only requires that you specify the encoding for your input messages. Once you start operating on the ciphertexts, the encoding will evolve dynamically to represent the range of possible values. When it is not possible to infer the encoding,  an output encoder will need to be specified.

For example, let $$m_1 $$and $$m_2$$ be the messages encoded into the interval $$[min_1, max_1]$$and respectively $$[min_2, max_2]$$. Then, the range of values of their addition is updated to $$[min_1+min_2, max_1+max_2]$$.

The last parameter, the number of **padding bits** is required to ensure the correctness of future computations. In a nutshell, they allow to keep the precision and granularity defined in the encoder while taking in account the potential carries. The processes related to the padding are details in the [Leveled Operations](../simple-operations/understanding-noise-and-padding.md#padding) section.

## Encoding a message into a plaintext

Under the hood, a Plaintext instance stores a vector of encoded messages, each with their own encoder. This enables Concrete to better manage performances. Thus, a plaintext in Concrete can be either a single encoded message, or a vector of encoded messages.

Encoding a message into a plaintext is rather simple:

```rust
// create a message in the interval
let message = -6.276;

// create a new Plaintext using the encoder's function
let p1: Plaintext = encoder.encode_single(message)?;
```

The encode function is versatile, meaning you can pass it a vector of messages instead of a single message. Internally, both are represented in the same way, with single-message plaintexts simply representing the values as a vector of size 1.

```rust
// create a list of messages in our interval
let messages = vec![-6.276, 4.3, 0.12, -1.1, 7.78];

// create a new Plaintext using the encoder's function
let p2: Plaintext = encoder.encode(&messages)?;
```

## Decoding a plaintext into a message

You can decode a plaintext back into a raw message using the [decode](super::super::pro_api::Encoder) method:

```rust
// decode the plaintext into a vector of messages
let output: Vec<f64> = p2.decode()?;
```

The decode method always returns a vector of messages, since this is how the plaintext stores values internally. If you only encoded one value, it will be stored in the decoded vector's first element.

{% hint style="warning" %}
Since encoding reduces the precision of the original message, the decoded message will not always match exactly the original message, but rather the closest value that the encoder can represent.
{% endhint %}

## Putting everything together

Here is an example program that specifies and uses an encoder, for a single message and a message vector:

```rust
/// file: main.rs
use concrete::*;

fn main() -> Result<(), CryptoAPIError> {
    // the encoder's parameters
    let min = -10.;
    let max = 10.;
    let precision = 8;
    let padding = 0;

    // create an Encoder instance
    let encoder = Encoder::new(min, max, precision, padding)?;

    // encode a single message
    let m1 = -6.276;
    let p1: Plaintext = encoder.encode_single(m1)?;

    // encode a vector of messages
    let m2 = vec![-6.276, 4.3, 0.12, -1.1, 7.78];
    let p2: Plaintext = encoder.encode(&m2)?;

    // decode the plaintext
    let o1: Vec<f64> = p1.decode()?;
    let o2: Vec<f64> = p2.decode()?;

    println!("{}", p1);
    println!("{}", p2);
    println!("m1 = {}, o1 = {:?}", m1, o1[0]);
    println!("m2 = {:?}, o2 = {:?}", m2, o2);
    Ok(())
}
```



