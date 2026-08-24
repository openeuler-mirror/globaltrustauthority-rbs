use std::fmt;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use cryptoki::context::{CInitializeArgs, Pkcs11};
use cryptoki::object::{Attribute, AttributeType, ObjectClass, ObjectHandle};
use cryptoki::session::{Session, UserType};
use cryptoki::slot::Slot;
use cryptoki::types::AuthPin;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use zeroize::Zeroizing;

use crate::resource::adapter::{BackendCapabilities, ResourceBackend};
use crate::resource::error::ResourceError;
use rbs_api_types::{GetResourceOptions, ResourceDesc};
use rbs_api_types::config::HsmConfig;

const HSM_SESSION_POOL_CAPACITY: usize = 8;

/// Valid resource_type values for the HSM backend.
/// `allowed_resource_types` in `HsmConfig` may only contain these; at least one
/// is required (enforced by `validation.rs` at startup).
const HSM_ALLOWED_RESOURCE_TYPES: &[&str] = &["key", "secret"];

/// HSM (PKCS#11) backend adapter.
///
/// Stores key material as opaque CKO_DATA blobs in an HSM token via PKCS#11.
/// PIN is read from an environment variable at construction time and never
/// stored in config files, logs, or Debug output.
///
/// The PKCS#11 module is loaded eagerly at construction (fail-fast): if the
/// module cannot be loaded, initialized, or the slot cannot be found,
/// `HsmBackend::new` returns an `Err`, preventing the service from starting
/// in a half-ready state (SR-001 §5.2).
pub struct HsmBackend {
    module_path: String,
    slot_label: String,
    pkcs11: Pkcs11,
    slot: Slot,
    pin: Zeroizing<String>,
    allowed_resource_types: Vec<String>,
    max_key_bytes: usize,
    timeout: Duration,
    sessions: Mutex<Vec<Session>>,
    semaphore: Arc<Semaphore>,
}

impl fmt::Debug for HsmBackend {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HsmBackend")
            .field("module_path", &self.module_path)
            .field("slot_label", &self.slot_label)
            .field("pin", &"[redacted]")
            .field("allowed_resource_types", &self.allowed_resource_types)
            .field("max_key_bytes", &self.max_key_bytes)
            .field("timeout", &self.timeout)
            .finish()
    }
}

impl HsmBackend {
    /// Construct an HsmBackend from configuration.
    ///
    /// Reads the PKCS#11 PIN from the environment variable specified by
    /// `cfg.credentials.pin_env`. Loads and initializes the PKCS#11 module
    /// eagerly (fail-fast): returns `Err` if the module cannot be loaded,
    /// initialized, or the slot cannot be found, preventing the service from
    /// starting in a half-ready state.
    pub fn new(cfg: &HsmConfig) -> Result<Self, String> {
        let pin = std::env::var(&cfg.credentials.pin_env).map_err(|_| {
            format!("HsmBackend: PIN environment variable '{}' is not set", cfg.credentials.pin_env)
        })?;
        for t in &cfg.allowed_resource_types {
            if !HSM_ALLOWED_RESOURCE_TYPES.contains(&t.as_str()) {
                return Err(format!(
                    "HsmBackend: invalid resource_type '{}' in allowed_resource_types; valid: {:?}",
                    t, HSM_ALLOWED_RESOURCE_TYPES
                ));
            }
        }

        // Eagerly load PKCS#11 module (fail-fast, SR-001 §5.2)
        let pkcs11 = Pkcs11::new(&cfg.module_path).map_err(|e| {
            format!("HsmBackend: failed to load PKCS#11 module '{}': {}", cfg.module_path, e)
        })?;
        pkcs11.initialize(CInitializeArgs::OsThreads).map_err(|e| {
            format!("HsmBackend: C_Initialize failed for module '{}': {}", cfg.module_path, e)
        })?;

        // Find slot by token label
        let slots = pkcs11.get_all_slots().map_err(|e| {
            format!("HsmBackend: C_GetSlotList failed: {}", e)
        })?;
        let slot = slots.into_iter().find(|s| {
            pkcs11.get_token_info(s.clone())
                .map(|info| info.label().trim() == cfg.slot.label)
                .unwrap_or(false)
        }).ok_or_else(|| {
            format!("HsmBackend: slot with label '{}' not found", cfg.slot.label)
        })?;

        log::info!(
            "HsmBackend: loaded module '{}', found slot '{}'",
            cfg.module_path, cfg.slot.label
        );

        Ok(Self {
            module_path: cfg.module_path.clone(),
            slot_label: cfg.slot.label.clone(),
            pkcs11,
            slot,
            pin: Zeroizing::new(pin),
            allowed_resource_types: cfg.allowed_resource_types.clone(),
            max_key_bytes: cfg.max_key_bytes as usize,
            timeout: Duration::from_secs(cfg.timeout as u64),
            sessions: Mutex::new(Vec::new()),
            semaphore: Arc::new(Semaphore::new(HSM_SESSION_POOL_CAPACITY)),
        })
    }

    /// Acquire a PKCS#11 session from the pool or open a new one.
    ///
    /// Returns the session paired with an `OwnedSemaphorePermit` whose
    /// lifetime bounds the borrowed session. The caller must hold the permit
    /// until `release_session` returns, so `HSM_SESSION_POOL_CAPACITY` truly
    /// limits concurrent open sessions instead of being released the instant
    /// the session is handed out.
    async fn acquire_session(&self) -> Result<(Session, OwnedSemaphorePermit), ResourceError> {
        // Acquire semaphore permit (bounded concurrency). The permit travels
        // with the session and is dropped by the caller after release_session,
        // bounding concurrent sessions for the whole borrow, not just the open.
        let permit = self.semaphore.clone().acquire_owned().await.map_err(|e| ResourceError::BackendError {
            detail: format!("HsmBackend semaphore error: {e}"),
        })?;

        // Try to reuse an existing session from the pool
        if let Some(session) = self.sessions.lock().map_err(|e| ResourceError::BackendError {
            detail: format!("HsmBackend sessions lock error: {e}"),
        })?.pop() {
            return Ok((session, permit));
        }

        // Open a new session and login
        let session = self.pkcs11.open_rw_session(self.slot.clone()).map_err(|e| {
            log::error!("HsmBackend: C_OpenSession failed: {}", e);
            ResourceError::BackendError { detail: "PKCS#11 open_session failed".to_string() }
        })?;
        let pin = AuthPin::new(self.pin.as_str().to_string());
        session.login(UserType::User, Some(&pin)).map_err(|e| {
            log::error!("HsmBackend: C_Login failed: {}", e);
            ResourceError::BackendError { detail: "PKCS#11 login failed".to_string() }
        })?;
        Ok((session, permit))
    }

    /// Return a session to the pool for reuse.
    fn release_session(&self, session: Session) {
        if let Ok(mut pool) = self.sessions.lock() {
            pool.push(session);
        }
    }
}

/// Build the PKCS#11 CKA_LABEL from the full resource descriptor so that
/// resources sharing the same `resource_name` but different repo/type do not
/// collide in the HSM token.
fn object_label(desc: &ResourceDesc) -> String {
    format!("{}/{}/{}", desc.repository_name, desc.resource_type, desc.resource_name)
}

/// Find a PKCS#11 object by its CKA_LABEL. Returns None if not found.
fn find_object_by_label(session: &Session, label: &str) -> Result<Option<ObjectHandle>, ResourceError> {
    let template = vec![Attribute::Label(label.as_bytes().to_vec())];
    let handles = session.find_objects(&template).map_err(|e| {
        log::error!("HsmBackend: C_FindObjects failed: {}", e);
        ResourceError::BackendError { detail: "PKCS#11 find_objects failed".to_string() }
    })?;
    Ok(handles.into_iter().next())
}

#[async_trait::async_trait]
impl ResourceBackend for HsmBackend {
    /// HSM declares PUT | DELETE: it can import/replace key material and
    /// destroy objects. It does not advertise CHECK (existence is inferred
    /// from the get path). Aligned with `module_interfaces.md` §3.2.
    fn capabilities(&self) -> BackendCapabilities {
        BackendCapabilities::PUT | BackendCapabilities::DELETE
    }

    /// Write/replace a PKCS#11 CKO_DATA object labelled with the full
    /// resource descriptor. `data` is the raw key material (Base64-decoded by
    /// the Service). If an object with the same label already exists it is
    /// destroyed first, so this is an idempotent put.
    async fn put_resource_content(
        &self,
        desc: &ResourceDesc,
        data: &[u8],
    ) -> Result<(), ResourceError> {
        // T5: input validation — content size
        if data.len() > self.max_key_bytes {
            log::error!(
                "HsmBackend: content size {} exceeds max_key_bytes {}",
                data.len(),
                self.max_key_bytes
            );
            return Err(ResourceError::ParamInvalid { field: "content" });
        }
        let (session, _permit) = self.acquire_session().await?;
        // Replace existing object: destroy then create (idempotent put)
        if let Some(handle) = find_object_by_label(&session, &object_label(desc))? {
            session.destroy_object(handle).map_err(|e| {
                log::error!("HsmBackend: C_DestroyObject failed during put: {}", e);
                ResourceError::BackendError { detail: "PKCS#11 destroy_object failed".to_string() }
            })?;
        }
        // Create object with CKO_DATA (D11: unified opaque blob storage)
        let template = vec![
            Attribute::Class(ObjectClass::DATA),
            Attribute::Label(object_label(desc).into_bytes()),
            Attribute::Value(data.to_vec()),
            Attribute::Token(true),
        ];
        session.create_object(&template).map_err(|e| {
            log::error!("HsmBackend: C_CreateObject failed: {}", e);
            ResourceError::BackendError { detail: "PKCS#11 create_object failed".to_string() }
        })?;
        self.release_session(session);
        // _permit drops here, releasing the semaphore permit AFTER the session
        // has been returned, keeping the borrow bounded for its full lifetime.
        Ok(())
    }

    async fn get_resource_content(
        &self,
        desc: &ResourceDesc,
        _opts: GetResourceOptions,
    ) -> Result<Zeroizing<Vec<u8>>, ResourceError> {
        // HSM does not use CSR — opts.csr_der is intentionally ignored.
        let (session, _permit) = self.acquire_session().await?;
        let handle = find_object_by_label(&session, &object_label(desc))?
            .ok_or_else(|| ResourceError::BackendNotFound)?;
        let attrs = session.get_attributes(handle, &[AttributeType::Value]).map_err(|e| {
            log::error!("HsmBackend: C_GetAttributeValue failed: {}", e);
            ResourceError::BackendError { detail: "PKCS#11 get_attributes failed".to_string() }
        })?;
        self.release_session(session);
        drop(_permit);
        for attr in attrs {
            if let Attribute::Value(bytes) = attr {
                return Ok(Zeroizing::new(bytes));
            }
        }
        Err(ResourceError::BackendNotFound)
    }

    /// Idempotent: destroy the object if present, otherwise Ok.
    async fn delete_resource(&self, desc: &ResourceDesc) -> Result<(), ResourceError> {
        let (session, _permit) = self.acquire_session().await?;
        if let Some(handle) = find_object_by_label(&session, &object_label(desc))? {
            session.destroy_object(handle).map_err(|e| {
                log::error!("HsmBackend: C_DestroyObject failed: {}", e);
                ResourceError::BackendError { detail: "PKCS#11 destroy_object failed".to_string() }
            })?;
        }
        self.release_session(session);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::resource::adapter::ResourceBackend;
    use rbs_api_types::config::{CredentialsConfig, SlotConfig};

    fn desc(rtype: &str, tag: &str) -> ResourceDesc {
        ResourceDesc {
            repository_name: "default".to_string(),
            resource_type: rtype.to_string(),
            resource_name: tag.to_string(),
        }
    }

    fn cfg(pin_env: &str, allowed: Vec<&str>, max_key_bytes: usize) -> HsmConfig {
        HsmConfig {
            module_path: "/nonexistent/path.so".to_string(),
            slot: SlotConfig { label: "test".to_string() },
            credentials: CredentialsConfig {
                pin_env: pin_env.to_string(),
            },
            allowed_resource_types: allowed.into_iter().map(String::from).collect(),
            max_key_bytes: max_key_bytes as u32,
            timeout: 30,
        }
    }

    /// Fail-fast: construction with a non-existent module path must return Err.
    #[test]
    fn test_new_fails_with_invalid_module() {
        std::env::set_var("TEST_HSM_PIN_FAIL", "1234");
        let result = HsmBackend::new(&cfg("TEST_HSM_PIN_FAIL", vec!["key"], 4096));
        assert!(result.is_err(), "HsmBackend::new must fail-fast on bad module path");
        let err = result.unwrap_err();
        assert!(
            err.contains("failed to load PKCS#11 module") || err.contains("C_Initialize"),
            "error should mention module load failure, got: {err}"
        );
    }

    /// Fail-fast: missing PIN env var must return Err at construction.
    #[test]
    fn test_new_fails_without_pin_env() {
        std::env::remove_var("TEST_HSM_PIN_MISSING");
        let result = HsmBackend::new(&cfg("TEST_HSM_PIN_MISSING", vec!["key"], 4096));
        assert!(result.is_err());
        assert!(
            result.unwrap_err().contains("PIN environment variable"),
            "error should mention PIN env var"
        );
    }

    /// Fail-fast: invalid resource_type in allowed_resource_types must return Err.
    #[test]
    fn test_new_fails_with_invalid_resource_type() {
        std::env::set_var("TEST_HSM_PIN_RT", "1234");
        let mut c = cfg("TEST_HSM_PIN_RT", vec!["key"], 4096);
        c.allowed_resource_types = vec!["invalid_type".to_string()];
        let result = HsmBackend::new(&c);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("invalid resource_type"));
    }

    // Hardware-dependent tests (require SoftHSM2) — marked #[ignore]
    // Run with: cargo test -p rbs-core --lib resource::adapter::hsm -- --ignored

    #[tokio::test]
    #[ignore = "requires SoftHSM2 and RBS_HSM_PIN_TEST env var"]
    async fn test_softhsm2_put_get_delete() {
        let cfg = HsmConfig {
            module_path: "/usr/lib/softhsm/libsofthsm2.so".to_string(),
            slot: SlotConfig { label: "rbs_test".to_string() },
            credentials: CredentialsConfig { pin_env: "RBS_HSM_PIN_TEST".to_string() },
            allowed_resource_types: vec!["key".to_string(), "secret".to_string()],
            max_key_bytes: 65536,
            timeout: 30,
        };
        let backend = HsmBackend::new(&cfg).expect("init");
        let key_desc = desc("key", "testobj");
        // Ensure clean state
        let _ = backend.delete_resource(&key_desc).await;
        // Put (create)
        backend
            .put_resource_content(&key_desc, b"test-key-material")
            .await
            .expect("put should succeed");
        // Get
        let content = backend
            .get_resource_content(&key_desc, GetResourceOptions { csr_der: None })
            .await
            .expect("get should succeed");
        assert_eq!(&*content, b"test-key-material");
        // Put (replace) is idempotent
        backend
            .put_resource_content(&key_desc, b"replaced-key-material")
            .await
            .expect("replace should succeed");
        let replaced = backend
            .get_resource_content(&key_desc, GetResourceOptions { csr_der: None })
            .await
            .expect("get after replace should succeed");
        assert_eq!(&*replaced, b"replaced-key-material");
        // Delete (idempotent)
        backend.delete_resource(&key_desc).await.expect("delete should succeed");
        backend.delete_resource(&key_desc).await.expect("delete should be idempotent");
        // After delete, get should report not found
        let after = backend
            .get_resource_content(&key_desc, GetResourceOptions { csr_der: None })
            .await;
        assert!(
            matches!(after, Err(ResourceError::BackendNotFound)),
            "expected BackendNotFound after delete, got {:?}", after
        );
    }

    #[tokio::test]
    #[ignore = "requires SoftHSM2 and RBS_HSM_PIN_TEST env var"]
    async fn test_softhsm2_put_rejects_oversized_content() {
        let cfg = HsmConfig {
            module_path: "/usr/lib/softhsm/libsofthsm2.so".to_string(),
            slot: SlotConfig { label: "rbs_test".to_string() },
            credentials: CredentialsConfig { pin_env: "RBS_HSM_PIN_TEST".to_string() },
            allowed_resource_types: vec!["key".to_string()],
            max_key_bytes: 32,
            timeout: 30,
        };
        let backend = HsmBackend::new(&cfg).expect("init");
        let big = vec![0u8; 64]; // exceeds max_key_bytes=32
        let result = backend.put_resource_content(&desc("key", "bigkey"), &big).await;
        assert!(matches!(result, Err(ResourceError::ParamInvalid { field: "content" })));
    }

    #[test]
    #[ignore = "requires SoftHSM2 and RBS_HSM_PIN_TEST env var"]
    fn test_debug_redacts_pin() {
        let cfg = HsmConfig {
            module_path: "/usr/lib/softhsm/libsofthsm2.so".to_string(),
            slot: SlotConfig { label: "rbs_test".to_string() },
            credentials: CredentialsConfig {
                pin_env: "TEST_HSM_PIN_DEBUG".to_string(),
            },
            allowed_resource_types: vec!["key".to_string(), "secret".to_string()],
            max_key_bytes: 65536,
            timeout: 30,
        };
        std::env::set_var("TEST_HSM_PIN_DEBUG", "my-secret-pin");
        let backend = HsmBackend::new(&cfg).expect("init");
        let debug_str = format!("{:?}", backend);
        assert!(debug_str.contains("[redacted]"));
        assert!(!debug_str.contains("my-secret-pin"));
    }
}
