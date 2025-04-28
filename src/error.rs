use keyring::error::Error as KeyRingError;
use linux_keyutils::KeyError as KeyUtilsError;
use std::ops::Deref;

/// Internal newtype to convert linux_keyutils::KeyError to
/// keyring::error::Error implicitly.
pub(crate) struct KeyStoreError(pub(crate) KeyUtilsError);

impl Deref for KeyStoreError {
    type Target = KeyUtilsError;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl From<KeyUtilsError> for KeyStoreError {
    fn from(err: KeyUtilsError) -> KeyStoreError {
        KeyStoreError(err)
    }
}

impl From<KeyStoreError> for KeyRingError {
    fn from(err: KeyStoreError) -> KeyRingError {
        match err.0 {
            // Experimentation has shown that the keyutils implementation can return a lot of
            // different errors that all mean "no such key", depending on where in the invalidation
            // processing the [get_password](KeyutilsCredential::get_password) call is made.
            KeyUtilsError::KeyDoesNotExist
            | KeyUtilsError::AccessDenied
            | KeyUtilsError::KeyRevoked
            | KeyUtilsError::KeyExpired => KeyRingError::NoEntry,
            KeyUtilsError::InvalidDescription => KeyRingError::Invalid(
                "description".to_string(),
                "rejected by platform".to_string(),
            ),
            KeyUtilsError::InvalidArguments => {
                KeyRingError::Invalid("password".to_string(), "rejected by platform".to_string())
            }
            other => KeyRingError::PlatformFailure(other.into()),
        }
    }
}
