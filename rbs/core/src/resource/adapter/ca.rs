//! CA (CMPv2) resource backend.
//!
//! Acts as a CMP client (RFC 4210/9480 transport) against a CA/RA.
//! On an Attest GET carrying a CSR, RBS builds a `p10cr` PKIMessage
//! (raw PKCS#10 CSR in body), signs with protection key, POSTs to CA URL,
//! verifies response protection against trust anchors, maps PKIStatus,
//! and returns the issued certificate DER.

use std::fmt;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

use dashmap::DashMap;
use zeroize::Zeroizing;

use crate::resource::adapter::{BackendCapabilities, ResourceBackend};
use crate::resource::error::ResourceError;
use rbs_api_types::{GetResourceOptions, ResourceDesc};
use rbs_api_types::config::CaConfig;

use cmpv2::body::PkiBody;
use cmpv2::certified_key_pair::CertOrEncCert;
use cmpv2::gen::InfoTypeAndValue;
use cmpv2::header::{PkiHeader, Pvno};
use cmpv2::message::{PkiMessage, ProtectedPart};
use cmpv2::response::{CertRepMessage, CertResponse};
use cmpv2::status::PkiStatus;
use der::asn1::{Any, BitString, GeneralizedTime, ObjectIdentifier, OctetString};
use der::{Decode, Encode, Tag};
use openssl::hash::{hash, MessageDigest};
use openssl::pkey::{PKey, Private, Public};
use openssl::sign::{Signer, Verifier};
use openssl::x509::X509;
use x509_cert::ext::pkix::name::GeneralName;
use x509_cert::spki::AlgorithmIdentifierOwned;

const CMP_CONTENT_TYPE: &str = "application/pkixcmp";
const SHA256_RSA_OID: &str = "1.2.840.113549.1.1.11";
const ECDSA_SHA256_OID: &str = "1.2.840.10045.4.3.2";
const ECDSA_SHA384_OID: &str = "1.2.840.10045.4.3.3";
const ECDSA_SHA512_OID: &str = "1.2.840.10045.4.3.4";
/// id-it-certProfile: carries the cert profile name in PKIHeader.generalInfo.
const IT_CERT_PROFILE_OID: &str = "1.3.6.1.5.5.7.4.21";

/// Valid resource_type values for the CA backend.
/// `allowed_resource_types` in `CaConfig` may only contain these; at least one
/// is required (enforced by `validation.rs` at startup).
const CA_ALLOWED_RESOURCE_TYPES: &[&str] = &["cert"];

struct CacheEntry {
    cert: Zeroizing<Vec<u8>>,
    expires_at: Instant,
    last_access: Instant,
}

pub struct CABackend {
    url: String,
    allowed_resource_types: Vec<String>,
    max_response_bytes: u64,
    timeout: Duration,
    /// CMP request signing key. It must live for the backend's lifetime (it
    /// signs every request), so it cannot be zeroized while in use; OpenSSL
    /// clear-frees its secret components when the key object is dropped
    /// (`RSA_free`/`EC_KEY_free` reach `BN_clear_free` for the private parts).
    /// The PEM/DER file bytes it was parsed from are zeroized in
    /// `load_private_key`.
    protection_key: PKey<Private>,
    /// CMP request protection algorithm OID derived from `protection_key`
    /// (RSA→sha256WithRSA, EC P256/P384/P521→ecdsa-with-SHA256/384/512).
    protection_alg_oid: &'static str,
    protection_cert_der: Vec<u8>,
    extra_certs_der: Vec<Vec<u8>>,
    anchors: Vec<PKey<Public>>,
    responder_cert_der: Vec<u8>,
    cert_profile: String,
    http: reqwest::Client,
    max_entries: usize,
    ttl: Duration,
    cache: DashMap<String, CacheEntry>,
    inflight: DashMap<String, Arc<tokio::sync::Mutex<()>>>,
}

impl fmt::Debug for CABackend {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CABackend")
            .field("url", &self.url)
            .field("allowed_resource_types", &self.allowed_resource_types)
            .field("max_response_bytes", &self.max_response_bytes)
            .field("timeout_secs", &self.timeout.as_secs())
            .field("protection_key", &"[redacted]")
            .field("anchor_count", &self.anchors.len())
            .finish()
    }
}

impl CABackend {
    pub fn new(config: &CaConfig) -> Result<Self, String> {
        for t in &config.allowed_resource_types {
            if !CA_ALLOWED_RESOURCE_TYPES.contains(&t.as_str()) {
                return Err(format!(
                    "invalid resource_type '{}' in allowed_resource_types; valid: {:?}",
                    t, CA_ALLOWED_RESOURCE_TYPES
                ));
            }
        }
        let prot_certs = load_certs(&config.message_protection_cert_file, "protection cert")?;
        if prot_certs.is_empty() {
            return Err("no certificate in message_protection_cert_file".to_string());
        }
        let protection_cert_der = prot_certs[0].to_der().map_err(|e| format!("encode cert: {e}"))?;
        let extra_certs_der: Vec<Vec<u8>> = prot_certs.iter().skip(1)
            .map(|c| c.to_der().unwrap_or_else(|e| {
                log::warn!("CA backend: skipping extra cert (encode failed): {e}");
                Vec::new()
            })).collect();

        let protection_key = load_private_key(&config.message_protection_key_file)?;
        match prot_certs[0].public_key() {
            Ok(cert_pub) => {
                let a = protection_key.public_key_to_der().map_err(|e| format!("key der: {e}"))?;
                let b = cert_pub.public_key_to_der().map_err(|e| format!("cert der: {e}"))?;
                if a != b {
                    return Err("protection key does not match protection cert".to_string());
                }
            }
            Err(e) => return Err(format!("extract cert public key: {e}")),
        }

        // Derive the request protection algorithm from the key type (fail-fast:
        // unsupported key types/curves abort startup, not the first request).
        let protection_alg_oid = protection_alg_oid_for_key(&protection_key)?;

        let ta_certs = load_certs(&config.response_protection_trust_anchors_file, "trust anchors")?;
        if ta_certs.is_empty() {
            return Err("no certificate in trust anchors file".to_string());
        }
        let mut anchors = Vec::new();
        for c in &ta_certs {
            let pk = c.public_key().map_err(|e| format!("anchor public key: {e}"))?;
            anchors.push(pk);
        }
        let responder_cert_der = ta_certs[0]
            .to_der()
            .map_err(|e| format!("encode responder cert: {e}"))?;

        let mut b = reqwest::Client::builder()
            .timeout(Duration::from_secs(config.timeout as u64));
        if config.https.verify {
            if !config.https.ca_file.is_empty() {
                let ca_pem = std::fs::read(&config.https.ca_file)
                    .map_err(|e| format!("read ca_file: {e}"))?;
                for ca in reqwest::Certificate::from_pem_bundle(&ca_pem)
                    .map_err(|e| format!("parse ca_file: {e}"))? {
                    b = b.add_root_certificate(ca);
                }
            }
        } else {
            log::warn!("CA backend: https.verify=false (non-production)");
            b = b.danger_accept_invalid_certs(true);
        }
        let http = b.build().map_err(|e| format!("build HTTP client: {e}"))?;

        log::info!("CA backend initialized: url='{}', anchors={}", config.url, anchors.len());

        Ok(Self {
            url: config.url.clone(),
            allowed_resource_types: config.allowed_resource_types.clone(),
            max_response_bytes: config.max_response_bytes as u64,
            timeout: Duration::from_secs(config.timeout as u64),
            protection_key,
            protection_alg_oid,
            protection_cert_der,
            extra_certs_der,
            anchors,
            responder_cert_der,
            cert_profile: config.cert_profile.clone(),
            http,
            max_entries: config.idempotency.max_entries as usize,
            ttl: Duration::from_secs(config.idempotency.ttl_seconds as u64),
            cache: DashMap::new(),
            inflight: DashMap::new(),
        })
    }

    fn idem_key(csr_der: &[u8], desc: &ResourceDesc) -> String {
        let h = hash(MessageDigest::sha256(), csr_der)
            .map(|d| d.to_vec()).unwrap_or_default();
        format!(
            "{}:{}:{}:{}",
            desc.repository_name,
            desc.resource_type,
            desc.resource_name,
            hex(&h)
        )
    }

    async fn issue(&self, desc: &ResourceDesc, csr_der: &[u8]) -> Result<Zeroizing<Vec<u8>>, ResourceError> {
        let cert_req = x509_cert::request::CertReq::from_der(csr_der).map_err(|e| {
            log::error!("CA: CSR DER parse failed: {}", e);
            ResourceError::ParamInvalid { field: "csr" }
        })?;

        let prot_cert = x509_cert::Certificate::from_der(&self.protection_cert_der).map_err(|e| {
            log::error!("CA: protection cert parse failed: {}", e);
            ResourceError::BackendError { detail: "protection cert invalid".to_string() }
        })?;
        let responder_cert =
            x509_cert::Certificate::from_der(&self.responder_cert_der).map_err(|e| {
                log::error!("CA: responder cert parse failed: {}", e);
                ResourceError::BackendError { detail: "responder cert invalid".to_string() }
            })?;

        let general_info = if self.cert_profile.is_empty() {
            None
        } else {
            // XiPKI encodes id-it-certProfile's infoValue as
            // SEQUENCE { UTF8String <profile> }; a bare UTF8String is
            // rejected by CmpUtil.extractCertProfile (DERUTF8String).
            let profile_bytes = self.cert_profile.as_bytes();
            let mut utf8_der: Vec<u8> = vec![0x0C]; // UTF8String tag
            let len = profile_bytes.len();
            if len < 0x80 {
                utf8_der.push(len as u8);
            } else {
                let mut tmp = len;
                let mut len_bytes: Vec<u8> = Vec::new();
                while tmp > 0 {
                    len_bytes.insert(0, (tmp & 0xFF) as u8);
                    tmp >>= 8;
                }
                utf8_der.push(0x80 | len_bytes.len() as u8);
                utf8_der.extend_from_slice(&len_bytes);
            }
            utf8_der.extend_from_slice(profile_bytes);
            let profile_val = Any::new(Tag::Sequence, &utf8_der[..])
                .map_err(|e| ResourceError::BackendError {
                    detail: format!("encode cert_profile: {e}"),
                })?;
            Some(vec![InfoTypeAndValue {
                oid: ObjectIdentifier::new_unwrap(IT_CERT_PROFILE_OID),
                value: Some(profile_val),
            }])
        };

        let txid = rand_bytes(16);
        let nonce = rand_bytes(16);
        let header = PkiHeader {
            pvno: Pvno::Cmp2000,
            sender: GeneralName::DirectoryName(prot_cert.tbs_certificate.subject.clone()),
            recipient: GeneralName::DirectoryName(
                responder_cert.tbs_certificate.subject.clone(),
            ),
            message_time: GeneralizedTime::from_system_time(SystemTime::now()).ok(),
            protection_alg: Some(AlgorithmIdentifierOwned {
                oid: ObjectIdentifier::new_unwrap(self.protection_alg_oid),
                parameters: None,
            }),
            sender_kid: None,
            recip_kid: None,
            trans_id: Some(OctetString::new(txid).map_err(|e| {
                ResourceError::BackendError { detail: format!("OctetString: {e}") }
            })?),
            sender_nonce: Some(OctetString::new(nonce).map_err(|e| {
                ResourceError::BackendError { detail: format!("OctetString: {e}") }
            })?),
            recip_nonce: None,
            free_text: None,
            general_info,
        };

        let body = PkiBody::P10cr(cert_req);

        let protected = ProtectedPart { header: header.clone(), body: body.clone() };
        let protected_der = protected.to_der().map_err(|e| {
            ResourceError::BackendError { detail: format!("ProtectedPart encode: {e}") }
        })?;
        let prot_digest = digest_for_oid(self.protection_alg_oid)?;
        let mut signer = Signer::new(prot_digest, &self.protection_key).map_err(|e| {
            ResourceError::BackendError { detail: format!("protection signer init: {e}") }
        })?;
        signer.update(&protected_der).map_err(|e| {
            ResourceError::BackendError { detail: format!("protection signer update: {e}") }
        })?;
        let sig = signer.sign_to_vec().map_err(|e| {
            ResourceError::BackendError { detail: format!("protection signer finalize: {e}") }
        })?;

        let mut extra: Vec<x509_cert::Certificate> = Vec::with_capacity(1 + self.extra_certs_der.len());
        extra.push(prot_cert);
        for der in &self.extra_certs_der {
            match x509_cert::Certificate::from_der(der) {
                Ok(c) => extra.push(c),
                Err(e) => log::warn!("CA backend: skipping malformed extra cert: {e}"),
            }
        }

        let msg = PkiMessage {
            header,
            body,
            protection: Some(BitString::from_bytes(&sig).map_err(|e| {
                ResourceError::BackendError { detail: format!("BitString: {e}") }
            })?),
            extra_certs: Some(extra),
        };
        let req_der = msg.to_der().map_err(|e| {
            ResourceError::BackendError { detail: format!("PKIMessage encode: {e}") }
        })?;

        log::debug!("CA: POST {} ({} bytes p10cr)", self.url, req_der.len());
        let resp = self.http
            .post(&self.url)
            .header(reqwest::header::CONTENT_TYPE, CMP_CONTENT_TYPE)
            .header(reqwest::header::ACCEPT, CMP_CONTENT_TYPE)
            .body(req_der)
            .send().await
            .map_err(|e| {
                log::error!("CA: CMP POST failed: {}", e);
                ResourceError::BackendError { detail: format!("cmp transport: {e}") }
            })?;

        if let Some(cl) = resp.content_length() {
            if cl > self.max_response_bytes {
                return Err(ResourceError::BackendError { detail: "cmp response too large".to_string() });
            }
        }
        let status = resp.status();
        let body_bytes = resp.bytes().await.map_err(|e| {
            ResourceError::BackendError { detail: format!("cmp body: {e}") }
        })?;
        if body_bytes.len() as u64 > self.max_response_bytes {
            return Err(ResourceError::BackendError { detail: "cmp response too large".to_string() });
        }
        if !status.is_success() {
            return Err(ResourceError::BackendError { detail: format!("cmp http {}", status) });
        }

        let resp_msg = PkiMessage::from_der(&body_bytes).map_err(|e| {
            log::error!("CA: CMP response parse failed: {}", e);
            ResourceError::BackendError { detail: "cmp response parse".to_string() }
        })?;

        let resp_protected = ProtectedPart { header: resp_msg.header.clone(), body: resp_msg.body.clone() };
        let resp_protected_der = resp_protected.to_der().map_err(|e| {
            ResourceError::BackendError { detail: format!("response ProtectedPart: {e}") }
        })?;
        let Some(protection_bits) = resp_msg.protection else {
            return Err(ResourceError::BackendError { detail: "cmp response unprotected".to_string() });
        };
        let sig_bytes = protection_bits.as_bytes().unwrap_or(&[]).to_vec();
        // Select the verifier digest from the response's declared protection_alg
        // (honour SHA-256/384/512) instead of hardcoding SHA-256.
        let digest = match resp_msg.header.protection_alg.as_ref() {
            Some(alg) => digest_for_protection_alg(alg)?,
            None => {
                return Err(ResourceError::BackendError {
                    detail: "cmp response missing protection_alg".to_string(),
                });
            }
        };
        log::info!(
            "CA: resp protection_alg={:?}, protection_bits={}, anchors={}",
            resp_msg.header.protection_alg, sig_bytes.len(), self.anchors.len()
        );
        let mut verified = false;
        for (i, anchor) in self.anchors.iter().enumerate() {
            let key_id = format!("{:?}", anchor.id());
            match Verifier::new(digest, anchor) {
                Ok(mut v) => {
                    let upd = v.update(&resp_protected_der);
                    let ver = upd.is_ok() && v.verify(&sig_bytes).unwrap_or(false);
                    log::info!("CA: anchor[{}] key_id={:?} verify={}", i, key_id, ver);
                    if ver {
                        verified = true;
                        break;
                    }
                }
                Err(e) => log::warn!(
                    "CA: anchor[{}] key_id={:?} Verifier::new err: {}",
                    i, key_id, e
                ),
            }
        }
        if !verified {
            log::error!("CA: CMP response protection verification failed");
            return Err(ResourceError::BackendError {
                detail: "cmp response protection verification failed".to_string(),
            });
        }

        let cert_rep = match &resp_msg.body {
            PkiBody::Cp(CertRepMessage { response, .. })
            | PkiBody::Ip(CertRepMessage { response, .. })
            | PkiBody::Kup(CertRepMessage { response, .. })
            | PkiBody::Ccp(CertRepMessage { response, .. }) => response,
            PkiBody::Error(_) => {
                return Err(ResourceError::BackendError { detail: "cmp error response".to_string() });
            }
            other => {
                return Err(ResourceError::BackendError {
                    detail: format!("unexpected cmp body: {:?}", other),
                });
            }
        };

        for cr in cert_rep {
            let r = extract_cert_from_response(cr)?;
            if let Some(der) = r {
                log::info!(
                    "CA: certificate issued for tag='{}' ({} bytes)",
                    desc.resource_name, der.len()
                );
                return Ok(Zeroizing::new(der));
            }
        }
        Err(ResourceError::BackendError { detail: "cmp response carried no certificate".to_string() })
    }
}

/// Detect whether bytes are PEM (ASCII text starting with `-----BEGIN`) or DER.
fn is_pem(bytes: &[u8]) -> bool {
    bytes.starts_with(b"-----BEGIN")
}

/// Load one or more X509 certificates from a file that may be PEM (bundle) or
/// a single DER-encoded certificate. DER cannot carry a multi-cert bundle;
/// for chains use PEM.
fn load_certs(path: &str, label: &str) -> Result<Vec<X509>, String> {
    let bytes = std::fs::read(path).map_err(|e| format!("read {label} file '{path}': {e}"))?;
    if is_pem(&bytes) {
        X509::stack_from_pem(&bytes)
            .map_err(|e| format!("parse {label} PEM '{path}': {e}"))
    } else {
        X509::from_der(&bytes)
            .map(|c| vec![c])
            .map_err(|e| format!("parse {label} DER '{path}': {e}"))
    }
}

/// Load a private key from a file that may be PEM or DER (PKCS#8/PKCS#1).
///
/// The file bytes hold the complete private key material, so the buffer is
/// wrapped in `Zeroizing` and cleared as soon as the `PKey` has been parsed
/// (the parse copies the material into OpenSSL-owned memory; the input buffer
/// is not referenced afterwards). The parsed key object's own cleanup story is
/// documented on the `protection_key` field.
fn load_private_key(path: &str) -> Result<PKey<Private>, String> {
    let bytes =
        Zeroizing::new(std::fs::read(path).map_err(|e| format!("read key file '{path}': {e}"))?);
    if is_pem(&bytes) {
        PKey::private_key_from_pem(&bytes)
            .map_err(|e| format!("parse key PEM '{path}': {e}"))
    } else {
        PKey::private_key_from_der(&bytes)
            .map_err(|e| format!("parse key DER '{path}': {e}"))
    }
}

/// Map a CMP protection algorithm OID to the OpenSSL `MessageDigest` used to
/// sign (request side) / verify (response side). Supports RSA
/// (sha{256,384,512}WithRSAEncryption) and ECDSA (ecdsa-with-SHA{256,384,512}).
/// A CA/gateway MAY respond with any of these; honour the declared algorithm
/// instead of hardcoding. Unsupported OIDs yield an explicit error rather than
/// silently mis-verifying.
fn digest_for_oid(oid: &str) -> Result<MessageDigest, ResourceError> {
    match oid {
        // RSA signature algorithms
        "1.2.840.113549.1.1.11" => Ok(MessageDigest::sha256()), // sha256WithRSAEncryption
        "1.2.840.113549.1.1.12" => Ok(MessageDigest::sha384()), // sha384WithRSAEncryption
        "1.2.840.113549.1.1.13" => Ok(MessageDigest::sha512()), // sha512WithRSAEncryption
        // ECDSA signature algorithms
        "1.2.840.10045.4.3.2" => Ok(MessageDigest::sha256()), // ecdsa-with-SHA256
        "1.2.840.10045.4.3.3" => Ok(MessageDigest::sha384()), // ecdsa-with-SHA384
        "1.2.840.10045.4.3.4" => Ok(MessageDigest::sha512()), // ecdsa-with-SHA512
        other => Err(ResourceError::BackendError {
            detail: format!("unsupported cmp protection alg OID: {other}"),
        }),
    }
}

/// Map a CMP response `protection_alg` to the OpenSSL digest via [`digest_for_oid`].
fn digest_for_protection_alg(
    alg: &AlgorithmIdentifierOwned,
) -> Result<MessageDigest, ResourceError> {
    digest_for_oid(&alg.oid.to_string())
}

/// Derive the CMP request protection algorithm OID from the protection key
/// type. RSA → sha256WithRSAEncryption; EC P-256/P-384/P-521 →
/// ecdsa-with-SHA256/384/512. Other key types / curves error (fail-fast in
/// `new()`, not the first request).
fn protection_alg_oid_for_key(key: &PKey<Private>) -> Result<&'static str, String> {
    match key.id() {
        openssl::pkey::Id::RSA => Ok(SHA256_RSA_OID),
        openssl::pkey::Id::EC => {
            let ec_key = key.ec_key().map_err(|_| {
                "protection key: invalid EC key".to_string()
            })?;
            let nid = ec_key
                .group()
                .curve_name()
                .unwrap_or(openssl::nid::Nid::from_raw(0));
            if nid == openssl::nid::Nid::X9_62_PRIME256V1 {
                Ok(ECDSA_SHA256_OID)
            } else if nid == openssl::nid::Nid::SECP384R1 {
                Ok(ECDSA_SHA384_OID)
            } else if nid == openssl::nid::Nid::SECP521R1 {
                Ok(ECDSA_SHA512_OID)
            } else {
                Err(format!("unsupported EC curve for protection key: {:?}", nid))
            }
        }
        other => Err(format!("unsupported protection key type: {:?}", other)),
    }
}

fn extract_cert_from_response(cr: &CertResponse<'_>) -> Result<Option<Vec<u8>>, ResourceError> {
    match cr.status.status {
        PkiStatus::Waiting => Err(ResourceError::CaRequestPending),
        PkiStatus::Rejection => Err(ResourceError::BackendError { detail: "cmp rejection".to_string() }),
        PkiStatus::Accepted | PkiStatus::GrantedWithMods => {
            if let Some(ref ckp) = cr.certified_key_pair {
                if let CertOrEncCert::Certificate(ref cert) = ckp.cert_or_enc_cert {
                    let der = cert.to_der().map_err(|e| {
                        ResourceError::BackendError { detail: format!("cert encode: {e}") }
                    })?;
                    return Ok(Some(der));
                }
            }
            Ok(None)
        }
        _ => Err(ResourceError::BackendError { detail: format!("cmp status: {:?}", cr.status.status) }),
    }
}

fn rand_bytes(n: usize) -> Vec<u8> {
    use rand::RngCore;
    let mut buf = vec![0u8; n];
    rand::rng().fill_bytes(&mut buf);
    buf
}

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

const _: () = {
    // Compile-time proof that CABackend is Send + Sync (required by ResourceBackend).
    // Trait-bound form avoids the dead-code warning a fn-body assertion triggers.
    fn _assert_send_sync() where CABackend: Send + Sync {}
};

#[async_trait::async_trait]
impl ResourceBackend for CABackend {
    /// CA is a get-only backend: certificates are issued on demand from a CSR
    /// during `get_resource_content` (CMPv2 flow). It cannot put, delete, or
    /// check — `ResourceService` only registers metadata for CA resources.
    fn capabilities(&self) -> BackendCapabilities {
        BackendCapabilities::empty()
    }

    async fn get_resource_content(
        &self,
        desc: &ResourceDesc,
        opts: GetResourceOptions,
    ) -> Result<Zeroizing<Vec<u8>>, ResourceError> {
        let Some(csr_der) = opts.csr_der.as_ref() else {
            log::warn!(
                "CA get_resource_content denied: CSR required for tag='{}'",
                desc.resource_name
            );
            return Err(ResourceError::CsrRequired);
        };

        let key = Self::idem_key(csr_der, desc);

        if let Some(mut e) = self.cache.get_mut(&key) {
            if Instant::now() < e.expires_at {
                e.last_access = Instant::now();
                log::debug!(
                    "CA: idempotency cache hit for tag='{}'",
                    desc.resource_name
                );
                return Ok(e.cert.clone());
            }
        }

        let lock = self.inflight.entry(key.clone())
            .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(()))).clone();
        let _g = lock.lock().await;

        if let Some(mut e) = self.cache.get_mut(&key) {
            if Instant::now() < e.expires_at {
                e.last_access = Instant::now();
                let _ = self.inflight.remove(&key);
                return Ok(e.cert.clone());
            }
        }

        let cert = match self.issue(desc, csr_der).await {
            Ok(c) => c,
            Err(e) => {
                let _ = self.inflight.remove(&key);
                return Err(e);
            }
        };

        if self.cache.len() >= self.max_entries {
            evict_lru(&self.cache, self.max_entries);
        }
        self.cache.insert(key.clone(), CacheEntry {
            cert: cert.clone(),
            expires_at: Instant::now() + self.ttl,
            last_access: Instant::now(),
        });
        // Clean up the transient inflight entry now that the cache holds the
        // result, so dedup entries cannot accumulate unboundedly.
        let _ = self.inflight.remove(&key);
        Ok(cert)
    }
}

/// Evict expired entries first, then evict the least-recently-used entry
/// (true LRU keyed on `last_access`) until the cache fits `max_entries`.
/// Extracted as a free function so the LRU policy is unit-testable without
/// standing up a full CMP mock.
fn evict_lru(cache: &DashMap<String, CacheEntry>, max_entries: usize) {
    let now = Instant::now();
    // Pass 1: TTL-based reclamation of expired entries.
    let expired: Vec<String> = cache.iter()
        .filter(|e| e.expires_at <= now)
        .map(|e| e.key().clone()).collect();
    for k in expired { cache.remove(&k); }
    // Pass 2: still over capacity → evict the least-recently-used entry
    // (true LRU on last_access, not arbitrary/DashMap iteration order).
    while cache.len() >= max_entries {
        let victim = cache.iter()
            .min_by_key(|e| e.last_access)
            .map(|e| e.key().clone());
        match victim {
            Some(k) => { cache.remove(&k); }
            None => break,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::resource::adapter::ResourceBackend;

    fn desc(tag: &str) -> ResourceDesc {
        ResourceDesc {
            repository_name: "default".to_string(),
            resource_type: "cert".to_string(),
            resource_name: tag.to_string(),
        }
    }

    #[test]
    fn test_hex_lowercase() {
        assert_eq!(hex(&[0x01, 0xff]), "01ff");
    }

    #[test]
    fn test_idem_key_stable() {
        let d = desc("c1");
        let k1 = CABackend::idem_key(b"csr1", &d);
        let k2 = CABackend::idem_key(b"csr1", &d);
        let k3 = CABackend::idem_key(b"csr2", &d);
        let k4 = CABackend::idem_key(b"csr1", &desc("c2"));
        assert_eq!(k1, k2, "same csr + desc -> same key");
        assert_ne!(k1, k3, "different csr -> different key");
        assert_ne!(k1, k4, "different tag -> different key");
    }

    #[test]
    fn test_rand_bytes_length() {
        let b = rand_bytes(32);
        assert_eq!(b.len(), 32);
    }

    /// LRU eviction: with cache full, the entry whose `last_access` is oldest
    /// is evicted (not an arbitrary DashMap-order entry). Insert three entries
    /// out of order, touch the first one, then force eviction at capacity 3 and
    /// assert the LRU (never re-touched) is the one removed.
    #[test]
    fn test_evict_lru_removes_oldest_accessed() {
        let cache: DashMap<String, CacheEntry> = DashMap::new();
        let far_future = Instant::now() + Duration::from_secs(3600);

        // Insert "a" first (oldest insert), "b", then "c".
        cache.insert("a".to_string(), CacheEntry {
            cert: Zeroizing::new(b"a".to_vec()),
            expires_at: far_future,
            last_access: Instant::now(),
        });
        // Give each insert a distinct, monotonic last_access by sleeping.
        std::thread::sleep(Duration::from_millis(2));
        cache.insert("b".to_string(), CacheEntry {
            cert: Zeroizing::new(b"b".to_vec()),
            expires_at: far_future,
            last_access: Instant::now(),
        });
        std::thread::sleep(Duration::from_millis(2));
        let oldest = Instant::now();
        cache.insert("c".to_string(), CacheEntry {
            cert: Zeroizing::new(b"c".to_vec()),
            expires_at: far_future,
            last_access: oldest,
        });

        // Touch "a" so it becomes most-recently-used; "b" is now the LRU.
        std::thread::sleep(Duration::from_millis(2));
        if let Some(mut e) = cache.get_mut("a") {
            e.last_access = Instant::now();
        }

        // Capacity is 3 and we already have 3 → eviction targets the LRU ("b").
        evict_lru(&cache, 3);
        assert!(cache.contains_key("a"), "MRU 'a' must survive");
        assert!(cache.contains_key("c"), "'c' must survive");
        assert!(!cache.contains_key("b"), "LRU 'b' must be evicted, got: {:?}", cache.iter().map(|e| e.key().clone()).collect::<Vec<_>>());
    }

    /// Eviction prefers expired entries over LRU: an expired entry is removed
    /// even if it was the most-recently-used.
    #[test]
    fn test_evict_lru_prefers_expired_over_lru() {
        let cache: DashMap<String, CacheEntry> = DashMap::new();
        let now = Instant::now();
        let far_future = now + Duration::from_secs(3600);

        // "fresh" is the LRU by access time but not expired.
        cache.insert("fresh".to_string(), CacheEntry {
            cert: Zeroizing::new(b"f".to_vec()),
            expires_at: far_future,
            last_access: now,
        });
        // "stale" is the MRU but expired.
        cache.insert("stale".to_string(), CacheEntry {
            cert: Zeroizing::new(b"s".to_vec()),
            expires_at: now - Duration::from_secs(1), // already expired
            last_access: now + Duration::from_millis(5),
        });

        evict_lru(&cache, 2);
        assert!(!cache.contains_key("stale"), "expired 'stale' must be reclaimed first");
        assert!(cache.contains_key("fresh"), "non-expired 'fresh' must survive");
    }

    /// `digest_for_protection_alg` maps the RSA + ECDSA signature OIDs to a
    /// matching OpenSSL digest (Ok) and rejects unknown algorithms (Err)
    /// instead of mis-verifying. Concrete digest value is proven end-to-end by
    /// `ca_backend_issue_extracts_certificate` (RSA/SHA-256 path).
    #[test]
    fn test_digest_for_protection_alg_oid_mapping() {
        let mk = |oid: &str| AlgorithmIdentifierOwned {
            oid: ObjectIdentifier::new_unwrap(oid),
            parameters: None,
        };
        // Known RSA signature OIDs → Ok.
        assert!(digest_for_protection_alg(&mk("1.2.840.113549.1.1.11")).is_ok(), "sha256WithRSA must map");
        assert!(digest_for_protection_alg(&mk("1.2.840.113549.1.1.12")).is_ok(), "sha384WithRSA must map");
        assert!(digest_for_protection_alg(&mk("1.2.840.113549.1.1.13")).is_ok(), "sha512WithRSA must map");
        // Known ECDSA signature OIDs → Ok.
        assert!(digest_for_protection_alg(&mk("1.2.840.10045.4.3.2")).is_ok(), "ecdsa-with-SHA256 must map");
        assert!(digest_for_protection_alg(&mk("1.2.840.10045.4.3.3")).is_ok(), "ecdsa-with-SHA384 must map");
        assert!(digest_for_protection_alg(&mk("1.2.840.10045.4.3.4")).is_ok(), "ecdsa-with-SHA512 must map");

        // Unsupported OID → explicit error (no silent SHA-256 fallback).
        match digest_for_protection_alg(&mk("1.2.3.4.5.6.7.8")) {
            Err(ResourceError::BackendError { detail }) => {
                assert!(detail.contains("1.2.3.4.5.6.7.8"), "detail must name the OID, got: {detail}");
            }
            Ok(_) => panic!("expected BackendError for unsupported OID, got Ok"),
            Err(e) => panic!("expected BackendError for unsupported OID, got other error: {e:?}"),
        }
    }

    /// `load_private_key` accepts both PEM and DER encodings and returns the
    /// same key it parsed. The input buffer is now `Zeroizing`-wrapped (the
    /// PEM/DER bytes are the raw key material); this test pins the loading
    /// behaviour so the wrap cannot silently break parsing.
    #[test]
    fn test_load_private_key_pem_and_der() {
        let rsa = openssl::rsa::Rsa::generate(2048).expect("generate RSA key");
        let pkey = openssl::pkey::PKey::from_rsa(rsa).expect("wrap RSA key in PKey");

        let dir = tempfile::tempdir().expect("create temp dir");

        // PEM path (PKCS#8 PEM) → private_key_from_pem.
        let pem = pkey.private_key_to_pem_pkcs8().expect("encode PKCS#8 PEM");
        let pem_path = dir.path().join("protection.pem");
        std::fs::write(&pem_path, &pem).expect("write PEM file");
        let loaded =
            load_private_key(pem_path.to_str().expect("PEM path is UTF-8")).expect("load PEM key");
        assert_eq!(
            loaded.private_key_to_pem_pkcs8().expect("re-encode loaded key"),
            pem,
            "PEM round-trip must yield the same key"
        );

        // DER path (type-specific DER via i2d_PrivateKey) → private_key_from_der
        // (d2i_AutoPrivateKey accepts both traditional and PKCS#8 DER).
        let der = pkey.private_key_to_der().expect("encode DER");
        let der_path = dir.path().join("protection.der");
        std::fs::write(&der_path, &der).expect("write DER file");
        let loaded =
            load_private_key(der_path.to_str().expect("DER path is UTF-8")).expect("load DER key");
        assert_eq!(
            loaded.private_key_to_der().expect("re-encode loaded key"),
            der,
            "DER round-trip must yield the same key"
        );

        // Non-existent file must fail with a read error mentioning the path.
        let missing = load_private_key(dir.path().join("missing.pem").to_str().expect("path is UTF-8"));
        assert!(missing.is_err(), "missing key file must be an error");
        assert!(
            missing.unwrap_err().contains("read key file"),
            "error must mention the read failure"
        );
    }
}
