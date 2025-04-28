use super::{KeyutilsCredential, KeyutilsCredentialBuilder};
use keyring::credential::{CredentialApi, CredentialBuilderApi, CredentialPersistence};
use keyring::{Entry, Error as KeyRingError};

#[test]
fn test_persistence() {
    assert!(matches!(
        KeyutilsCredentialBuilder::new().persistence(),
        CredentialPersistence::UntilReboot
    ))
}

#[test]
fn test_keyring_integration() {
    keyring::set_default_credential_builder(KeyutilsCredentialBuilder::new());
    let entry = Entry::new("myservice", "user1").expect("Couldn't create entry");
    test_round_trip_no_delete("Default backend for keyring-rs", &entry, "secret1");
}

fn entry_new(service: &str, user: &str) -> Entry {
    let cred = KeyutilsCredential::new_with_target(None, service, user);
    match cred {
        Ok(cred) => Entry::new_with_credential(Box::new(cred)),
        Err(err) => {
            panic!("Couldn't create entry (service: {service}, user: {user}): {err:?}")
        }
    }
}

fn generate_random_string() -> String {
    use fastrand;
    use std::iter::repeat_with;
    repeat_with(fastrand::alphanumeric).take(30).collect()
}

fn generate_random_bytes() -> Vec<u8> {
    use fastrand;
    use std::iter::repeat_with;
    repeat_with(|| fastrand::u8(..)).take(24).collect()
}

fn test_round_trip_no_delete(case: &str, entry: &Entry, in_pass: &str) {
    entry
        .set_password(in_pass)
        .unwrap_or_else(|err| panic!("Can't set password for {case}: {err:?}"));
    let out_pass = entry
        .get_password()
        .unwrap_or_else(|err| panic!("Can't get password for {case}: {err:?}"));
    assert_eq!(
        in_pass, out_pass,
        "Passwords don't match for {case}: set='{in_pass}', get='{out_pass}'",
    )
}

/// A basic round-trip unit test given an entry and a password.
fn test_round_trip(case: &str, entry: &Entry, in_pass: &str) {
    test_round_trip_no_delete(case, entry, in_pass);
    entry
        .delete_credential()
        .unwrap_or_else(|err| panic!("Can't delete password for {case}: {err:?}"));
    let password = entry.get_password();
    assert!(
        matches!(password, Err(KeyRingError::NoEntry)),
        "Read deleted password for {case}",
    );
}

/// A basic round-trip unit test given an entry and a secret.
pub fn test_round_trip_secret(case: &str, entry: &Entry, in_secret: &[u8]) {
    entry
        .set_secret(in_secret)
        .unwrap_or_else(|err| panic!("Can't set secret for {case}: {err:?}"));
    let out_secret = entry
        .get_secret()
        .unwrap_or_else(|err| panic!("Can't get secret for {case}: {err:?}"));
    assert_eq!(
        in_secret, &out_secret,
        "Passwords don't match for {case}: set='{in_secret:?}', get='{out_secret:?}'",
    );
    entry
        .delete_credential()
        .unwrap_or_else(|err| panic!("Can't delete password for {case}: {err:?}"));
    let password = entry.get_secret();
    assert!(
        matches!(password, Err(KeyRingError::NoEntry)),
        "Read deleted password for {case}",
    );
}

#[test]
fn test_empty_service_and_user() {
    let name = generate_random_string();
    let in_pass = "doesn't matter";
    test_round_trip("empty user", &entry_new(&name, ""), in_pass);
    test_round_trip("empty service", &entry_new("", &name), in_pass);
    test_round_trip("empty service & user", &entry_new("", ""), in_pass);
}

#[test]
fn test_invalid_parameter() {
    let credential = KeyutilsCredential::new_with_target(Some(""), "service", "user");
    assert!(
        matches!(credential, Err(KeyRingError::Invalid(_, _))),
        "Created entry with empty target"
    );
}

#[test]
fn test_missing_entry() {
    let name = generate_random_string();
    let entry = entry_new(&name, &name);
    assert!(
        matches!(entry.get_password(), Err(KeyRingError::NoEntry)),
        "Missing entry has password"
    )
}

#[test]
fn test_round_trip_ascii_password() {
    let name = generate_random_string();
    let entry = entry_new(&name, &name);
    test_round_trip("ascii password", &entry, "test ascii password");
}

#[test]
fn test_round_trip_non_ascii_password() {
    let name = generate_random_string();
    let entry = entry_new(&name, &name);
    test_round_trip("non-ascii password", &entry, "このきれいな花は桜です");
}

#[test]
fn test_round_trip_random_secret() {
    let name = generate_random_string();
    let entry = entry_new(&name, &name);
    let secret = generate_random_bytes();
    test_round_trip_secret("non-ascii password", &entry, secret.as_slice());
}

#[test]
fn test_update() {
    let name = generate_random_string();
    let entry = entry_new(&name, &name);
    test_round_trip_no_delete("initial ascii password", &entry, "test ascii password");
    test_round_trip(
        "updated non-ascii password",
        &entry,
        "このきれいな花は桜です",
    );
}

#[test]
fn test_noop_get_update_attributes() {
    use std::collections::HashMap;

    let name = generate_random_string();
    let entry = entry_new(&name, &name);
    assert!(
        matches!(entry.get_attributes(), Err(KeyRingError::NoEntry)),
        "Read missing credential in attribute test",
    );
    let mut map: HashMap<&str, &str> = HashMap::new();
    map.insert("test attribute name", "test attribute value");
    assert!(
        matches!(entry.update_attributes(&map), Err(KeyRingError::NoEntry)),
        "Updated missing credential in attribute test",
    );
    // create the credential and test again
    entry
        .set_password("test password for attributes")
        .unwrap_or_else(|err| panic!("Can't set password for attribute test: {err:?}"));
    match entry.get_attributes() {
        Err(err) => panic!("Couldn't get attributes: {err:?}"),
        Ok(attrs) if attrs.is_empty() => {}
        Ok(attrs) => panic!("Unexpected attributes: {attrs:?}"),
    }
    assert!(
        matches!(entry.update_attributes(&map), Ok(())),
        "Couldn't update attributes in attribute test",
    );
    match entry.get_attributes() {
        Err(err) => panic!("Couldn't get attributes after update: {err:?}"),
        Ok(attrs) if attrs.is_empty() => {}
        Ok(attrs) => panic!("Unexpected attributes after update: {attrs:?}"),
    }
    entry
        .delete_credential()
        .unwrap_or_else(|err| panic!("Can't delete credential for attribute test: {err:?}"));
    assert!(
        matches!(entry.get_attributes(), Err(KeyRingError::NoEntry)),
        "Read deleted credential in attribute test",
    );
}

#[test]
fn test_empty_password() {
    let entry = entry_new("empty password service", "empty password user");
    assert!(
        matches!(entry.set_password(""), Err(KeyRingError::Invalid(_, _))),
        "Able to set empty password"
    );
}

#[test]
fn test_get_credential() {
    let name = generate_random_string();
    let entry = entry_new(&name, &name);
    let credential: &KeyutilsCredential = entry
        .get_credential()
        .downcast_ref()
        .expect("Not a Keyutils credential");
    assert!(
        entry.get_secret().is_err(),
        "Platform credential shouldn't exist yet!"
    );
    entry
        .set_password("test get_credential")
        .expect("Can't set password for get_credential");
    assert!(credential.get_secret().is_ok());
    entry
        .delete_credential()
        .expect("Couldn't delete after get_credential");
    assert!(matches!(entry.get_password(), Err(KeyRingError::NoEntry)));
}
