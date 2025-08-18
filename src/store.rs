use std::collections::HashMap;
use std::fmt::Formatter;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use keyring_core::Entry;
use keyring_core::api::{CredentialPersistence, CredentialStoreApi};
use keyring_core::attributes::parse_attributes;
use keyring_core::error::{Error, Result};

use super::Cred;

/// The builder for keyutils credentials
#[derive(Debug, Clone)]
pub struct Store {
    pub id: String,
    pub delimiters: [String; 3],
    pub service_no_delimiter: bool,
}

impl Store {
    /// Create the default store: prefix `keyring:`, divider '@', no suffix.
    ///
    /// This is the configuration that matches the legacy keyring for this store.
    pub fn new() -> Result<Arc<Self>> {
        Ok(Self::new_internal(
            ["keyring:".to_string(), "@".to_string(), "".to_string()],
            false,
        ))
    }

    /// Create a custom-configured store.
    ///
    /// The delimiter config options are `prefix`, `divider`, and `suffix`. They
    /// default to `keyring:`, `@`, and the empty string.
    ///
    /// If you want to be sure that key descriptions cannot be ambiguous, specify
    /// the config option `service_no_delimiter` to `true`.
    pub fn new_with_configuration(config: &HashMap<&str, &str>) -> Result<Arc<Self>> {
        let config = parse_attributes(
            &["prefix", "divider", "suffix", "service_no_delimiter"],
            config,
        )?;
        let prefix = config
            .get("prefix")
            .map(|s| s.as_str())
            .unwrap_or("keyring:")
            .to_string();
        let divider = config
            .get("divider")
            .map(|s| s.as_str())
            .unwrap_or("@")
            .to_string();
        let suffix = config
            .get("suffix")
            .map(|s| s.as_str())
            .unwrap_or("")
            .to_string();
        let service_no_delimiter = match config.get("service_no_delimiter").map(|s| s.as_str()) {
            None => false,
            Some("true") => true,
            Some("false") => false,
            Some(_) => {
                return Err(Error::Invalid(
                    "service_no_delimiter".to_string(),
                    "must be true or false".to_string(),
                ));
            }
        };
        Ok(Self::new_internal(
            [prefix, divider, suffix],
            service_no_delimiter,
        ))
    }

    fn new_internal(delimiters: [String; 3], service_no_delimiter: bool) -> Arc<Self> {
        let now = SystemTime::now();
        let elapsed = if now.lt(&UNIX_EPOCH) {
            UNIX_EPOCH.duration_since(now).unwrap()
        } else {
            now.duration_since(UNIX_EPOCH).unwrap()
        };
        Arc::new(Store {
            id: format!(
                "Crate version {}, Instantiated at {}",
                env!("CARGO_PKG_VERSION"),
                elapsed.as_secs_f64()
            ),
            delimiters,
            service_no_delimiter,
        })
    }
}

impl CredentialStoreApi for Store {
    /// See the keyring-core API docs.
    fn vendor(&self) -> String {
        "Linux keyutils, https://crates.io/crates/linux-keyutils-keyring-store".to_string()
    }

    /// See the keyring-core API docs.
    fn id(&self) -> String {
        self.id.clone()
    }

    /// See the keyring-core API docs.
    ///
    /// Building a credential does not create a key in the store.
    /// It's setting a password that does that.
    fn build(
        &self,
        service: &str,
        user: &str,
        modifiers: Option<&HashMap<&str, &str>>,
    ) -> Result<Entry> {
        let mods = parse_attributes(&["description"], modifiers.unwrap_or(&HashMap::new()))?;
        let description = mods.get("description").map(|s| s.as_str());
        let cred = Cred::build_from_specifiers(
            description,
            &self.delimiters,
            self.service_no_delimiter,
            service,
            user,
        )?;
        Ok(Entry::new_with_credential(Arc::new(cred)))
    }

    /// See the keyring-core API docs.
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    /// See the keyring-core API docs.
    ///
    /// Since this keystore keeps credentials in kernel memory, they vanish on reboot
    fn persistence(&self) -> CredentialPersistence {
        CredentialPersistence::UntilReboot
    }

    /// See the keychain-core API docs.
    fn debug_fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        std::fmt::Debug::fmt(self, f)
    }
}
