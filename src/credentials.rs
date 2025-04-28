use super::error::KeyStoreError;
use keyring::credential::CredentialApi;
use linux_keyutils::{KeyRing, KeyRingIdentifier};

/// Representation of a keyutils credential.
///
/// Since the CredentialBuilderApi::build method does not provide
/// an initial secret, and it is impossible to have 0-length keys,
/// this representation holds a linux_keyutils::KeyRing instead
/// of a linux_keyutils::Key.
///
/// The added benefit of this approach
/// is that any call to get_password before set_password is done
/// will result in a proper error as the key does not exist until
/// set_password is called.
#[derive(Debug, Clone)]
pub struct KeyutilsCredential {
    /// Host session keyring
    pub session: KeyRing,
    /// Host persistent keyring
    pub persistent: Option<KeyRing>,
    /// Description of the key entry
    pub description: String,
}

impl CredentialApi for KeyutilsCredential {
    /// Set a password in the underlying store
    ///
    /// This will overwrite the entry if it already exists since
    /// it's using `add_key` under the hood.
    ///
    /// Returns an [Invalid](keyring::error::Error::Invalid) error if the password
    /// is empty, because keyutils keys cannot have empty values.
    fn set_secret(&self, secret: &[u8]) -> keyring::error::Result<()> {
        if secret.is_empty() {
            return Err(keyring::error::Error::Invalid(
                "secret".to_string(),
                "cannot be empty".to_string(),
            ));
        }
        self.set(secret)?;
        Ok(())
    }

    // TODO: Temporarily required until default is provided by the keyring
    // crate.
    fn set_password(&self, password: &str) -> keyring::Result<()> {
        self.set_secret(password.as_bytes())
    }

    /// Retrieve a secret from the underlying store
    ///
    /// This requires a call to `Key::read`.
    fn get_secret(&self) -> keyring::error::Result<Vec<u8>> {
        let buffer = self.get()?;
        Ok(buffer)
    }

    // TODO: Temporarily required until default is provided by the keyring
    // crate.
    fn get_password(&self) -> keyring::Result<String> {
        keyring::error::decode_password(self.get_secret()?)
    }

    /// Delete a password from the underlying store.
    ///
    /// Under the hood this uses `Key::invalidate` to immediately
    /// invalidate the key and prevent any further successful
    /// searches.
    ///
    /// Note that the keyutils implementation uses caching,
    /// and the caches take some time to clear,
    /// so a key that has been invalidated may still be found
    /// by get_password if it's called within milliseconds
    /// in *the same process* that deleted the key.
    fn delete_credential(&self) -> keyring::error::Result<()> {
        self.remove()?;
        Ok(())
    }

    /// Cast the credential object to std::any::Any.  This allows clients
    /// to downcast the credential to its concrete type so they
    /// can do platform-specific things with it.
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    /// Expose the concrete debug formatter for use via the [keyring::Credential] trait
    fn debug_fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Debug::fmt(self, f)
    }
}

impl KeyutilsCredential {
    /// Create the platform credential for a Keyutils entry.
    ///
    /// An explicit target string is interpreted as the KeyRing to use for the entry.
    /// If none is provided, then we concatenate the user and service in the string
    /// `keyring-rs:user@service`.
    pub fn new_with_target(
        target: Option<&str>,
        service: &str,
        user: &str,
    ) -> keyring::error::Result<Self> {
        Ok(KeyutilsCredential::new(target, service, user)?)
    }

    /// Internal constructor that bubbles up the underlying keyutils error
    fn new(target: Option<&str>, service: &str, user: &str) -> Result<Self, KeyStoreError> {
        // Obtain the session keyring
        let session = KeyRing::from_special_id(KeyRingIdentifier::Session, false)?;

        // Link the persistent keyring to the session
        let persistent = KeyRing::get_persistent(KeyRingIdentifier::Session).ok();

        // Construct the credential with a URI-style description
        let description = match target {
            Some("") => return Err(KeyStoreError(linux_keyutils::KeyError::InvalidArguments)),
            Some(value) => value.to_string(),
            None => format!("keyring-rs:{user}@{service}"),
        };
        Ok(Self {
            session,
            persistent,
            description,
        })
    }

    /// Internal method to retrieve the underlying secret
    ///
    /// Will search for and re-link the existing key to the session and
    /// persistent keyrings to ensure the key doesn't time out.
    fn get(&self) -> Result<Vec<u8>, KeyStoreError> {
        // Verify that the key exists and is valid
        let key = self.session.search(&self.description)?;

        // Directly re-link to the session keyring
        // If a logout occurred, it will only be linked to the
        // persistent keyring, and needs to be added again.
        self.session.link_key(key)?;

        // Directly re-link to the persistent keyring
        // If it expired, it will only be linked to the
        // session keyring, and needs to be added again.
        if let Some(keyring) = self.persistent {
            keyring.link_key(key)?;
        }

        // Read in the key (making sure we have enough room)
        let data = key.read_to_vec()?;
        Ok(data)
    }

    /// Internal method to set the underlying secret
    ///
    /// Will add the key directly to the session and link it to the
    /// persistent keyring when available.
    fn set<T: AsRef<[u8]>>(&self, secret: T) -> Result<(), KeyStoreError> {
        // Add to the session keyring
        let key = self.session.add_key(&self.description, &secret)?;

        // Directly link to the persistent keyring as well
        if let Some(keyring) = self.persistent {
            keyring.link_key(key).map_err(KeyStoreError)?;
        }
        Ok(())
    }

    /// Internal method to remove the underlying secret
    ///
    /// Performs a search and invalidates the key when found.
    fn remove(&self) -> Result<(), KeyStoreError> {
        // Verify that the key exists and is valid
        let key = self.session.search(&self.description)?;

        // Invalidate the key immediately
        key.invalidate()?;
        Ok(())
    }
}
