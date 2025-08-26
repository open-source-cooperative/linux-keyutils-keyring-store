# Linux Keyutils Keyring Store

This library provides a credential store for use with the [keyring ecosystem](https://github.com/open-source-cooperative/keyring-rs/wiki/Keyring) that uses the Linux key-management facility (keyctl).

## Usage

To use this keychain-compatible credential store provider, you must take a dependency on the [keyring-core crate](https://crates.io/crates/keyring-core) and on [this crate](https://crates.io/crates/linux-keyutils-keyring-store). Then you can instantiate a credential store and set it as your default credential store as shown in the [sample program](examples/example.rs) in this crate.

## License

Licensed under either of the following at your discretion:

 * Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
 * MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you shall be dual licensed as above, without any
additional terms or conditions.
