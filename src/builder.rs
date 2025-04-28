use super::KeyutilsCredential;
use keyring::credential::{Credential, CredentialBuilderApi, CredentialPersistence};
use keyring::error::Result;

/// The builder for keyutils credentials
#[derive(Debug, Copy, Clone)]
pub struct KeyutilsCredentialBuilder {}

impl KeyutilsCredentialBuilder {
    pub fn new() -> Box<Self> {
        Box::new(KeyutilsCredentialBuilder {})
    }
}

impl CredentialBuilderApi for KeyutilsCredentialBuilder {
    /// Build a keyutils credential with the given target, service, and user.
    ///
    /// Building a credential does not create a key in the store.
    /// It's setting a password that does that.
    fn build(&self, target: Option<&str>, service: &str, user: &str) -> Result<Box<Credential>> {
        Ok(Box::new(KeyutilsCredential::new_with_target(
            target, service, user,
        )?))
    }

    /// Return an [Any](std::any::Any) reference to the credential builder.
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    /// Since this keystore keeps credentials in kernel memory,
    /// they vanish on reboot
    fn persistence(&self) -> CredentialPersistence {
        CredentialPersistence::UntilReboot
    }
}
