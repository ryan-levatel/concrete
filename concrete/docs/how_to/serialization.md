# Serialization

As explained in the Introduction, most types are meant to be shared with the server that performs the computations.

The easiest way to send these data to a server is to use the `serialization` and `deserialization` features. `concrete` uses the [serde](https://crates.io/crates/serde) framework. Serde's `Serialize` and `Deserialize` functions are implemented on Concrete's types.

To be able to serialize our data, we need to pick a [data format](https://serde.rs/#data-formats). For our use case, [bincode](https://crates.io/crates/bincode) is a good choice, mainly because it is a binary format.

```toml
# Cargo.toml

[dependencies]
# ...
concrete = { version = "0.2.0", features = ["integers", "serde"]}
bincode = "1.3.3"
```

```rust
// main.rs

use bincode;

use std::io::Cursor;

use concrete::{ConfigBuilder, ServerKey, generate_keys, set_server_key, FheUint8};
use concrete::prelude::*;

fn main() -> Result<(), Box<dyn std::error::Error>>{
    let config = ConfigBuilder::all_disabled()
        .enable_default_uint8()
        .build();

    let ( client_key, server_key) = generate_keys(config);

    let msg1 = 1;
    let msg2 = 0;

    let value_1 = FheUint8::encrypt(msg1, &client_key);
    let value_2 = FheUint8::encrypt(msg2, &client_key);

    // Prepare to send data to the server
    // The ClientKey is _not_ sent
    let mut serialized_data = Vec::new();
    bincode::serialize_into(&mut serialized_data, &server_key)?;
    bincode::serialize_into(&mut serialized_data, &value_1)?;
    bincode::serialize_into(&mut serialized_data, &value_2)?;

    // Simulate sending serialized data to a server and getting
    // back the serialized result
    let serialized_result = server_function(&serialized_data)?;
    let result: FheUint8 = bincode::deserialize(&serialized_result)?;

    let output: u8 = result.decrypt(&client_key);
    assert_eq!(output, msg1 + msg2);
    Ok(())
}


fn server_function(serialized_data: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut serialized_data = Cursor::new(serialized_data);
    let server_key: ServerKey = bincode::deserialize_from(&mut serialized_data)?;
    let ct_1: FheUint8 = bincode::deserialize_from(&mut serialized_data)?;
    let ct_2: FheUint8 = bincode::deserialize_from(&mut serialized_data)?;

    set_server_key(server_key);

    let result = ct_1 + ct_2;

    let serialized_result = bincode::serialize(&result)?;

    Ok(serialized_result)
}
```
