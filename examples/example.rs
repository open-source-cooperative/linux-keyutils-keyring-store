//! Example CLI app that creates, writes, reads, examines, and deletes an entry
//! in the keyutils keystore using APIs from the keyring crate.
use keyring::Entry;
use linux_keyutils_keyring::KeyutilsCredentialBuilder;

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
    println!("Entry with no target: {:?}", entry);
    entry.delete_credential().unwrap();
    let target: &'static str = "target used as description";
    let entry = Entry::new_with_target(target, "ignored", "ignored").unwrap();
    entry.set_password(password).unwrap();
    let retrieved = entry.get_password().unwrap();
    if retrieved != password {
        panic!("Passwords do not match");
    }
    println!("Entry with target: {:?}", entry);
    entry.delete_credential().unwrap();
}
