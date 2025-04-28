//! Example CLI app that creates, writes, reads, examines, and deletes an entry
//! in the keyutils keystore using APIs from the keyring crate.
//!
//! This example must be compiled with the keystore feature specified.
use keyring::Entry;
use linux_kernel_keystore::KeyutilsCredentialBuilder;

fn main() {
    // Set keyutils backend as the default store
    keyring::set_default_credential_builder(KeyutilsCredentialBuilder::new());

    let service = "service";
    let username = "user";
    let password = "<PASSWORD>";
    let entry = Entry::new(service, username).unwrap();
    entry.set_password(password).unwrap();
    let retrieved = entry.get_password().unwrap();
    if retrieved != password {
        panic!("Passwords do not match");
    }
    println!("Entry: {:?}", entry);
    entry.delete_credential().unwrap()
}
