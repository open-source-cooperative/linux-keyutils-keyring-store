# linux-kernel-keystore
[![cargo-badge-lib][]][cargo-lib] [![docs-badge-lib][]][docs-lib] [![license-badge][]][license] [![rust-version-badge][]][rust-version] [![build][]][build-url] [![codecov][]][codecov-url]

This library provides a credential store for use with the [keyring crate](https://crates.io/crates/keyring) that uses the Linux key-management facility (keyctl).

## Basic Usage

To use `linux-kernel-keystore`, first add this to your `Cargo.toml`:

```toml
[dependencies]
linux-kernel-keystore = "0.1"
```

To make this keystore the default for creation of keyring entries, construct a builder and use `set_default_credential_builder`:

```rust
use linux_kernel_keystore::KeyutilsCredentialBuilder;

fn main() {
    // Set keyutils backend as the default store
    keyring::set_default_credential_builder(KeyutilsCredentialBuilder::new());
}
```

For more information please view the full [documentation](https://docs.rs/linux-kernel-keystore). There is also a small example program in the [examples directory](examples/keystore.rs).

## License

Licensed under either of the following at your discretion:

 * Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
 * MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you shall be dual licensed as above, without any
additional terms or conditions.

[//]: # (badges)
[license-badge]: https://img.shields.io/badge/license-MIT/Apache--2.0-lightgray.svg?style=flat-square
[license]: #license
[rust-version-badge]: https://img.shields.io/badge/rust-latest%20stable-blue.svg?style=flat-square
[rust-version]: #rust-version-policy
[cargo-badge-lib]: https://img.shields.io/crates/v/linux-kernel-keystore.svg?style=flat-square&label=linux-keyutils
[cargo-lib]: https://crates.io/crates/linux-kernel-keystore
[docs-badge-lib]: https://img.shields.io/docsrs/linux-kernel-keystore/latest?style=flat-square
[docs-lib]: https://docs.rs/linux-kernel-keystore
[codecov]: https://img.shields.io/codecov/c/github/landhb/linux-kernel-keystore?style=flat-square
[codecov-url]: https://codecov.io/gh/landhb/linux-kernel-keystore
[build]: https://img.shields.io/github/actions/workflow/status/landhb/linux-kernel-keystore/checks.yml?branch=main&style=flat-square
[build-url]: https://github.com/landhb/linux-kernel-keystore/actions?query=workflow%3Achecks
