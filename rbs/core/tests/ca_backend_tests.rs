//! Integration test for the CA (CMPv2) backend against a mock CMP server.

use std::sync::{Arc, Mutex};

use der::asn1::{BitString, GeneralizedTime, ObjectIdentifier, OctetString};
use der::{Decode, Encode};
use openssl::hash::MessageDigest;
use openssl::pkey::PKey;
use openssl::sign::Signer;
use openssl::x509::{X509Builder, X509NameBuilder, X509};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use cmpv2::body::PkiBody;
use cmpv2::certified_key_pair::{CertOrEncCert, CertifiedKeyPair};
use cmpv2::header::{PkiHeader, Pvno};
use cmpv2::message::{PkiMessage, ProtectedPart};
use cmpv2::response::{CertRepMessage, CertResponse};
use cmpv2::status::{PkiStatus, PkiStatusInfo};
use x509_cert::ext::pkix::name::GeneralName;
use x509_cert::spki::AlgorithmIdentifierOwned;

use rbs_core::resource::adapter::ResourceBackend;
use rbs_core::resource::error::ResourceError;
use rbs_api_types::config::{CaConfig, HttpsConfig, IdempotencyConfig};

const SHA256_RSA_OID: &str = "1.2.840.113549.1.1.11";
const ECDSA_SHA256_OID: &str = "1.2.840.10045.4.3.2";

/// Mirror the production logic: pick a CMP protection algorithm OID + OpenSSL
/// digest from the signer key type so `build_response` works for both RSA
/// and EC responder keys.
fn oid_and_digest_for_key(key: &PKey<openssl::pkey::Private>) -> (&'static str, MessageDigest) {
    match key.id() {
        openssl::pkey::Id::RSA => (SHA256_RSA_OID, MessageDigest::sha256()),
        openssl::pkey::Id::EC => {
            let ec = key.ec_key().expect("EC key");
            let nid = ec.group().curve_name().unwrap_or(openssl::nid::Nid::from_raw(0));
            if nid == openssl::nid::Nid::X9_62_PRIME256V1 {
                (ECDSA_SHA256_OID, MessageDigest::sha256())
            } else {
                panic!("test only sets up EC P-256 responders, got nid {:?}", nid);
            }
        }
        other => panic!("unsupported responder key type in test: {:?}", other),
    }
}

/// Generate an EC P-256 private key for tests.
fn ec_p256_key() -> PKey<openssl::pkey::Private> {
    let group = openssl::ec::EcGroup::from_curve_name(openssl::nid::Nid::X9_62_PRIME256V1).unwrap();
    let ec = openssl::ec::EcKey::generate(&group).unwrap();
    PKey::from_ec_key(ec).unwrap()
}

fn self_signed(priv_key: &PKey<openssl::pkey::Private>, cn: &str) -> X509 {
    let mut b = X509Builder::new().unwrap();
    b.set_version(2).unwrap();
    let nb = openssl::asn1::Asn1Time::days_from_now(0).unwrap();
    let na = openssl::asn1::Asn1Time::days_from_now(365).unwrap();
    b.set_not_before(&nb).unwrap();
    b.set_not_after(&na).unwrap();
    let mut name = X509NameBuilder::new().unwrap();
    name.append_entry_by_text("CN", cn).unwrap();
    let name = name.build();
    b.set_subject_name(&name).unwrap();
    b.set_pubkey(priv_key).unwrap();
    b.sign(priv_key, MessageDigest::sha256()).unwrap();
    b.build()
}

fn write_cert_pem(cert: &X509, dir: &std::path::Path, name: &str) -> String {
    let p = dir.join(name);
    std::fs::write(&p, cert.to_pem().unwrap()).unwrap();
    p.to_string_lossy().into_owned()
}

fn write_key_pem(key: &PKey<openssl::pkey::Private>, dir: &std::path::Path, name: &str) -> String {
    let p = dir.join(name);
    std::fs::write(&p, key.private_key_to_pem_pkcs8().unwrap()).unwrap();
    p.to_string_lossy().into_owned()
}

fn rand_bytes(n: usize) -> Vec<u8> {
    use rand::RngCore;
    let mut buf = vec![0u8; n];
    rand::rng().fill_bytes(&mut buf);
    buf
}

/// Build a `ResourceDesc` for a CA resource under the `default` repository.
fn ca_desc(tag: &str) -> rbs_api_types::ResourceDesc {
    rbs_api_types::ResourceDesc {
        repository_name: "default".to_string(),
        resource_type: "cert".to_string(),
        resource_name: tag.to_string(),
    }
}

fn build_response(
    req: &PkiMessage<'_>,
    anchor_key: &PKey<openssl::pkey::Private>,
    anchor_cert_der: &[u8],
    issued_der: &[u8],
) -> Vec<u8> {
    build_response_inner(req, anchor_key, anchor_cert_der, issued_der, |_| {})
}

/// `build_response` with a header tweak hook, used by the anti-replay
/// regression tests to perturb the echoed trans_id / recip_nonce.
fn build_response_inner(
    req: &PkiMessage<'_>,
    anchor_key: &PKey<openssl::pkey::Private>,
    anchor_cert_der: &[u8],
    issued_der: &[u8],
    tweak_header: impl FnOnce(&mut PkiHeader<'_>),
) -> Vec<u8> {
    let anchor_cert = x509_cert::Certificate::from_der(anchor_cert_der).unwrap();
    let issued = x509_cert::Certificate::from_der(issued_der).unwrap();

    let (resp_alg_oid, resp_digest) = oid_and_digest_for_key(anchor_key);
    let mut resp_header = PkiHeader {
        pvno: Pvno::Cmp2000,
        sender: GeneralName::DirectoryName(anchor_cert.tbs_certificate.subject.clone()),
        recipient: req.header.sender.clone(),
        message_time: GeneralizedTime::from_system_time(std::time::SystemTime::now()).ok(),
        protection_alg: Some(AlgorithmIdentifierOwned {
            oid: ObjectIdentifier::new_unwrap(resp_alg_oid),
            parameters: None,
        }),
        sender_kid: None,
        recip_kid: None,
        trans_id: req.header.trans_id.clone(),
        recip_nonce: req.header.sender_nonce.clone(),
        sender_nonce: Some(OctetString::new(rand_bytes(16)).unwrap()),
        free_text: None,
        general_info: None,
    };
    tweak_header(&mut resp_header);

    let cert_response = CertResponse {
        cert_req_id: der::asn1::Int::new(&[0]).unwrap(),
        status: PkiStatusInfo { status: PkiStatus::Accepted, status_string: None, fail_info: None },
        certified_key_pair: Some(CertifiedKeyPair {
            cert_or_enc_cert: CertOrEncCert::Certificate(Box::new(issued)),
            priv_key: None,
            publication_info: None,
        }),
        rsp_info: None,
    };
    let body = PkiBody::Cp(CertRepMessage { ca_pubs: None, response: vec![cert_response] });

    let protected = ProtectedPart { header: resp_header.clone(), body: body.clone() };
    let protected_der = protected.to_der().unwrap();
    let mut signer = Signer::new(resp_digest, anchor_key).unwrap();
    signer.update(&protected_der).unwrap();
    let sig = signer.sign_to_vec().unwrap();

    let msg = PkiMessage {
        header: resp_header,
        body,
        protection: Some(BitString::from_bytes(&sig).unwrap()),
        extra_certs: Some(vec![anchor_cert]),
    };
    msg.to_der().unwrap()
}

struct CmpMock {
    addr: std::net::SocketAddr,
    handle: Option<std::thread::JoinHandle<()>>,
    shutdown: Arc<Mutex<bool>>,
}

impl CmpMock {
    fn start<F>(responder: F) -> Self
    where
        F: Fn(&[u8]) -> Option<Vec<u8>> + Send + Sync + 'static,
    {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        listener.set_nonblocking(true).unwrap();
        let shutdown = Arc::new(Mutex::new(false));
        let sh = shutdown.clone();
        let resp = Arc::new(responder);
        let handle = std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
            rt.block_on(async move {
                let listener = tokio::net::TcpListener::from_std(listener).unwrap();
                loop {
                    if *sh.lock().unwrap() { break; }
                    tokio::select! {
                        accept = listener.accept() => {
                            if let Ok((mut s, _)) = accept {
                                let resp = resp.clone();
                                tokio::spawn(async move {
                                    handle_conn(&mut s, move |b| resp(b)).await;
                                });
                            } else { tokio::time::sleep(std::time::Duration::from_millis(10)).await; }
                        }
                        _ = tokio::time::sleep(std::time::Duration::from_millis(10)) => {}
                    }
                }
            });
        });
        Self { addr, handle: Some(handle), shutdown }
    }
    fn url(&self) -> String { format!("http://{}", self.addr) }
}

impl Drop for CmpMock {
    fn drop(&mut self) {
        *self.shutdown.lock().unwrap() = true;
        if let Some(h) = self.handle.take() { let _ = h.join(); }
    }
}

async fn handle_conn<F>(s: &mut tokio::net::TcpStream, responder: F)
where
    F: Fn(&[u8]) -> Option<Vec<u8>> + Send + Sync,
{
    let mut buf = vec![0u8; 65536];
    let n = s.read(&mut buf).await.unwrap_or(0);
    let req = &buf[..n];
    let body = match req.windows(4).position(|w| w == b"\r\n\r\n") {
        Some(idx) => &req[idx + 4..],
        None => &req[..],
    };
    match responder(body) {
        Some(d) => {
            let head = format!("HTTP/1.1 200 OK\r\nContent-Type: application/pkixcmp\r\nContent-Length: {}\r\n\r\n", d.len());
            let _ = s.write_all(head.as_bytes()).await;
            let _ = s.write_all(&d).await;
        }
        None => {
            let _ = s.write_all(b"HTTP/1.1 500 Internal\r\nContent-Length: 0\r\n\r\n").await;
        }
    }
}

fn make_ca_config(
    url: String,
    prot_cert_file: String,
    prot_key_file: String,
    anchors_file: String,
) -> CaConfig {
    CaConfig {
        url,
        https: HttpsConfig::default(),
        message_protection_cert_file: prot_cert_file,
        message_protection_key_file: prot_key_file,
        response_protection_trust_anchors_file: anchors_file,
        cert_profile: String::new(),
        allowed_resource_types: vec!["cert".to_string()],
        max_response_bytes: 1_048_576,
        timeout: 10,
        idempotency: IdempotencyConfig::default(),
    }
}

#[tokio::test]
async fn ca_backend_issue_extracts_certificate() {
    let dir = tempfile::TempDir::new().unwrap();

    let anchor_key = PKey::from_rsa(openssl::rsa::Rsa::generate(2048).unwrap()).unwrap();
    let anchor_cert = self_signed(&anchor_key, "rbs-ca-mock-anchor");
    let anchor_der = anchor_cert.to_der().unwrap();
    let anchors_file = write_cert_pem(&anchor_cert, dir.path(), "anchor.pem");

    let client_key = PKey::from_rsa(openssl::rsa::Rsa::generate(2048).unwrap()).unwrap();
    let client_cert = self_signed(&client_key, "rbs-ca-mock-client");
    let prot_cert_file = write_cert_pem(&client_cert, dir.path(), "client.pem");
    let prot_key_file = write_key_pem(&client_key, dir.path(), "client.key");

    let issued_key = PKey::from_rsa(openssl::rsa::Rsa::generate(2048).unwrap()).unwrap();
    let issued_cert = self_signed(&issued_key, "issued-cert");
    let issued_der = issued_cert.to_der().unwrap();

    let mut rb = openssl::x509::X509ReqBuilder::new().unwrap();
    let mut nm = openssl::x509::X509NameBuilder::new().unwrap();
    nm.append_entry_by_text("CN", "workload").unwrap();
    let nm = nm.build();
    rb.set_subject_name(&nm).unwrap();
    rb.set_pubkey(&client_key).unwrap();
    rb.sign(&client_key, MessageDigest::sha256()).unwrap();
    let csr_der = rb.build().to_der().unwrap();

    let ak = anchor_key.clone();
    let issued_for_closure = issued_der.clone();
    let mock = CmpMock::start(move |req_body: &[u8]| {
        let req = PkiMessage::from_der(req_body).ok()?;
        if !matches!(req.body, PkiBody::P10cr(_)) { return None; }
        Some(build_response(&req, &ak, &anchor_der, &issued_for_closure))
    });

    let cfg = make_ca_config(mock.url(), prot_cert_file, prot_key_file, anchors_file);
    let ca = rbs_core::resource::adapter::CABackend::new(&cfg).expect("CA backend init");

    let desc = ca_desc("cert1");
    let opts = rbs_api_types::GetResourceOptions { csr_der: Some(zeroize::Zeroizing::new(csr_der.clone())) };
    let got = ca.get_resource_content(&desc, opts).await.expect("issue should return the cert");
    assert_eq!(got.as_slice(), &issued_der[..], "extracted cert must equal the issued DER");

    // Idempotency: second call within TTL returns cached
    let opts2 = rbs_api_types::GetResourceOptions { csr_der: Some(zeroize::Zeroizing::new(csr_der.clone())) };
    let got2 = ca.get_resource_content(&desc, opts2).await.expect("idempotent get");
    assert_eq!(got2.as_slice(), &issued_der[..]);
}

/// EC end-to-end: EC P-256 keys for both the responder (anchor) and the RBS
/// protection key. Proves ECDSA request signing (`protection_alg_oid_for_key`
/// → ecdsa-with-SHA256) and ECDSA response verification (`digest_for_oid` with
/// an EC anchor) both work — not just the RSA path.
#[tokio::test]
async fn ca_backend_issue_extracts_certificate_ec() {
    let dir = tempfile::TempDir::new().unwrap();

    let anchor_key = ec_p256_key();
    let anchor_cert = self_signed(&anchor_key, "rbs-ca-mock-anchor-ec");
    let anchor_der = anchor_cert.to_der().unwrap();
    let anchors_file = write_cert_pem(&anchor_cert, dir.path(), "anchor.pem");

    let client_key = ec_p256_key();
    let client_cert = self_signed(&client_key, "rbs-ca-mock-client-ec");
    let prot_cert_file = write_cert_pem(&client_cert, dir.path(), "client.pem");
    let prot_key_file = write_key_pem(&client_key, dir.path(), "client.key");

    let issued_key = ec_p256_key();
    let issued_cert = self_signed(&issued_key, "issued-cert-ec");
    let issued_der = issued_cert.to_der().unwrap();

    let mut rb = openssl::x509::X509ReqBuilder::new().unwrap();
    let mut nm = openssl::x509::X509NameBuilder::new().unwrap();
    nm.append_entry_by_text("CN", "workload-ec").unwrap();
    let nm = nm.build();
    rb.set_subject_name(&nm).unwrap();
    rb.set_pubkey(&client_key).unwrap();
    rb.sign(&client_key, MessageDigest::sha256()).unwrap();
    let csr_der = rb.build().to_der().unwrap();

    let ak = anchor_key.clone();
    let issued_for_closure = issued_der.clone();
    let mock = CmpMock::start(move |req_body: &[u8]| {
        let req = PkiMessage::from_der(req_body).ok()?;
        if !matches!(req.body, PkiBody::P10cr(_)) { return None; }
        Some(build_response(&req, &ak, &anchor_der, &issued_for_closure))
    });

    let cfg = make_ca_config(mock.url(), prot_cert_file, prot_key_file, anchors_file);
    let ca = rbs_core::resource::adapter::CABackend::new(&cfg).expect("CA backend init (EC)");

    let desc = ca_desc("cert1-ec");
    let opts = rbs_api_types::GetResourceOptions { csr_der: Some(zeroize::Zeroizing::new(csr_der.clone())) };
    let got = ca.get_resource_content(&desc, opts).await.expect("issue (EC) should return the cert");
    assert_eq!(got.as_slice(), &issued_der[..], "extracted EC cert must equal the issued DER");
}

#[tokio::test]
async fn ca_backend_missing_csr_returns_csr_required() {
    let dir = tempfile::TempDir::new().unwrap();
    let anchor_key = PKey::from_rsa(openssl::rsa::Rsa::generate(2048).unwrap()).unwrap();
    let anchor_cert = self_signed(&anchor_key, "anchor");
    let client_key = PKey::from_rsa(openssl::rsa::Rsa::generate(2048).unwrap()).unwrap();
    let client_cert = self_signed(&client_key, "client");
    let mock = CmpMock::start(move |_| None);

    let cfg = make_ca_config(
        mock.url(),
        write_cert_pem(&client_cert, dir.path(), "c.pem"),
        write_key_pem(&client_key, dir.path(), "c.key"),
        write_cert_pem(&anchor_cert, dir.path(), "a.pem"),
    );
    let ca = rbs_core::resource::adapter::CABackend::new(&cfg).expect("init");
    let opts = rbs_api_types::GetResourceOptions { csr_der: None };
    let desc = ca_desc("x");
    match ca.get_resource_content(&desc, opts).await {
        Err(ResourceError::CsrRequired) => {}
        other => panic!("Expected CsrRequired, got {:?}", other),
    }
}

#[tokio::test]
async fn ca_backend_waiting_returns_ca_request_pending() {
    let dir = tempfile::TempDir::new().unwrap();
    let anchor_key = PKey::from_rsa(openssl::rsa::Rsa::generate(2048).unwrap()).unwrap();
    let anchor_cert = self_signed(&anchor_key, "anchor");
    let anchor_der = anchor_cert.to_der().unwrap();
    let client_key = PKey::from_rsa(openssl::rsa::Rsa::generate(2048).unwrap()).unwrap();
    let client_cert = self_signed(&client_key, "client");

    let mut rb = openssl::x509::X509ReqBuilder::new().unwrap();
    let mut nm = openssl::x509::X509NameBuilder::new().unwrap();
    nm.append_entry_by_text("CN", "workload").unwrap();
    rb.set_subject_name(&nm.build()).unwrap();
    rb.set_pubkey(&client_key).unwrap();
    rb.sign(&client_key, MessageDigest::sha256()).unwrap();
    let csr_der = rb.build().to_der().unwrap();

    let ak = anchor_key.clone();
    let mock = CmpMock::start(move |req_body: &[u8]| {
        let req = PkiMessage::from_der(req_body).ok()?;
        let anchor_cert = x509_cert::Certificate::from_der(&anchor_der).unwrap();
        let resp_header = PkiHeader {
            pvno: Pvno::Cmp2000,
            sender: GeneralName::DirectoryName(anchor_cert.tbs_certificate.subject.clone()),
            recipient: req.header.sender.clone(),
            message_time: GeneralizedTime::from_system_time(std::time::SystemTime::now()).ok(),
            protection_alg: Some(AlgorithmIdentifierOwned {
                oid: ObjectIdentifier::new_unwrap(SHA256_RSA_OID),
                parameters: None,
            }),
            sender_kid: None, recip_kid: None,
            trans_id: req.header.trans_id.clone(),
            recip_nonce: req.header.sender_nonce.clone(),
            sender_nonce: Some(OctetString::new(rand_bytes(16)).unwrap()),
            free_text: None, general_info: None,
        };
        let cert_response = CertResponse {
            cert_req_id: der::asn1::Int::new(&[0]).unwrap(),
            status: PkiStatusInfo { status: PkiStatus::Waiting, status_string: None, fail_info: None },
            certified_key_pair: None, rsp_info: None,
        };
        let body = PkiBody::Cp(CertRepMessage { ca_pubs: None, response: vec![cert_response] });
        let protected = ProtectedPart { header: resp_header.clone(), body: body.clone() };
        let protected_der = protected.to_der().unwrap();
        let mut signer = Signer::new(MessageDigest::sha256(), &ak).unwrap();
        signer.update(&protected_der).unwrap();
        let sig = signer.sign_to_vec().unwrap();
        let msg = PkiMessage {
            header: resp_header, body,
            protection: Some(BitString::from_bytes(&sig).unwrap()),
            extra_certs: Some(vec![anchor_cert]),
        };
        Some(msg.to_der().unwrap())
    });

    let cfg = make_ca_config(
        mock.url(),
        write_cert_pem(&client_cert, dir.path(), "c.pem"),
        write_key_pem(&client_key, dir.path(), "c.key"),
        write_cert_pem(&anchor_cert, dir.path(), "a.pem"),
    );
    let ca = rbs_core::resource::adapter::CABackend::new(&cfg).expect("init");
    let opts = rbs_api_types::GetResourceOptions { csr_der: Some(zeroize::Zeroizing::new(csr_der)) };
    let desc = ca_desc("x");
    match ca.get_resource_content(&desc, opts).await {
        Err(ResourceError::CaRequestPending) => {}
        other => panic!("Expected CaRequestPending, got {:?}", other),
    }
}

#[tokio::test]
async fn ca_backend_bad_protection_returns_backend_error() {
    let dir = tempfile::TempDir::new().unwrap();
    let anchor_key = PKey::from_rsa(openssl::rsa::Rsa::generate(2048).unwrap()).unwrap();
    let anchor_cert = self_signed(&anchor_key, "anchor");
    let client_key = PKey::from_rsa(openssl::rsa::Rsa::generate(2048).unwrap()).unwrap();
    let client_cert = self_signed(&client_key, "client");
    let rogue_key = PKey::from_rsa(openssl::rsa::Rsa::generate(2048).unwrap()).unwrap();
    let rogue_cert = self_signed(&rogue_key, "rogue");
    let rogue_der = rogue_cert.to_der().unwrap();

    let mut rb = openssl::x509::X509ReqBuilder::new().unwrap();
    let mut nm = openssl::x509::X509NameBuilder::new().unwrap();
    nm.append_entry_by_text("CN", "workload").unwrap();
    rb.set_subject_name(&nm.build()).unwrap();
    rb.set_pubkey(&client_key).unwrap();
    rb.sign(&client_key, MessageDigest::sha256()).unwrap();
    let csr_der = rb.build().to_der().unwrap();

    let issued_key = PKey::from_rsa(openssl::rsa::Rsa::generate(2048).unwrap()).unwrap();
    let issued_cert = self_signed(&issued_key, "issued");
    let issued_der = issued_cert.to_der().unwrap();

    let rk = rogue_key.clone();
    let mock = CmpMock::start(move |req_body: &[u8]| {
        let req = PkiMessage::from_der(req_body).ok()?;
        if !matches!(req.body, PkiBody::P10cr(_)) { return None; }
        Some(build_response(&req, &rk, &rogue_der, &issued_der))
    });

    let cfg = make_ca_config(
        mock.url(),
        write_cert_pem(&client_cert, dir.path(), "c.pem"),
        write_key_pem(&client_key, dir.path(), "c.key"),
        write_cert_pem(&anchor_cert, dir.path(), "a.pem"),
    );
    let ca = rbs_core::resource::adapter::CABackend::new(&cfg).expect("init");
    let opts = rbs_api_types::GetResourceOptions { csr_der: Some(zeroize::Zeroizing::new(csr_der)) };
    let desc = ca_desc("x");
    match ca.get_resource_content(&desc, opts).await {
        Err(ResourceError::BackendError { .. }) => {}
        other => panic!("Expected BackendError (bad protection), got {:?}", other),
    }
}

// ---------------------------------------------------------------------------
// Anti-replay regression (security scan SV-03, RFC 4210 §5.1.1)
// ---------------------------------------------------------------------------

/// Shared setup for the anti-replay tests: a correctly signing mock CA whose
/// response header is perturbed by `tweak` before signing, so the response
/// carries a valid protection signature but a mismatched trans_id/recip_nonce.
async fn replay_setup(tweak: fn(&mut PkiHeader<'_>)) -> Result<(), ResourceError> {
    let dir = tempfile::TempDir::new().unwrap();

    let anchor_key = PKey::from_rsa(openssl::rsa::Rsa::generate(2048).unwrap()).unwrap();
    let anchor_cert = self_signed(&anchor_key, "replay-anchor");
    let anchor_der = anchor_cert.to_der().unwrap();
    let anchors_file = write_cert_pem(&anchor_cert, dir.path(), "anchor.pem");

    let client_key = PKey::from_rsa(openssl::rsa::Rsa::generate(2048).unwrap()).unwrap();
    let client_cert = self_signed(&client_key, "replay-client");
    let prot_cert_file = write_cert_pem(&client_cert, dir.path(), "client.pem");
    let prot_key_file = write_key_pem(&client_key, dir.path(), "client.key");

    let issued_key = PKey::from_rsa(openssl::rsa::Rsa::generate(2048).unwrap()).unwrap();
    let issued_cert = self_signed(&issued_key, "replay-issued");
    let issued_der = issued_cert.to_der().unwrap();

    let mut rb = openssl::x509::X509ReqBuilder::new().unwrap();
    let mut nm = openssl::x509::X509NameBuilder::new().unwrap();
    nm.append_entry_by_text("CN", "workload").unwrap();
    rb.set_subject_name(&nm.build()).unwrap();
    rb.set_pubkey(&client_key).unwrap();
    rb.sign(&client_key, MessageDigest::sha256()).unwrap();
    let csr_der = rb.build().to_der().unwrap();

    let ak = anchor_key.clone();
    let mock = CmpMock::start(move |req_body: &[u8]| {
        let req = PkiMessage::from_der(req_body).ok()?;
        if !matches!(req.body, PkiBody::P10cr(_)) { return None; }
        Some(build_response_inner(&req, &ak, &anchor_der, &issued_der, tweak))
    });

    let cfg = make_ca_config(mock.url(), prot_cert_file, prot_key_file, anchors_file);
    let ca = rbs_core::resource::adapter::CABackend::new(&cfg).expect("CA backend init");
    let desc = ca_desc("replay");
    let opts = rbs_api_types::GetResourceOptions { csr_der: Some(zeroize::Zeroizing::new(csr_der)) };
    ca.get_resource_content(&desc, opts).await.map(|_| ())
}

/// SV-03: a validly signed response whose trans_id does not echo the
/// request's trans_id must be rejected (stale/mismatched response replay).
#[tokio::test]
async fn ca_backend_rejects_trans_id_mismatch() {
    match replay_setup(|h| {
        h.trans_id = Some(OctetString::new(rand_bytes(16)).unwrap());
    })
    .await
    {
        Err(ResourceError::BackendError { detail }) => {
            assert!(detail.contains("trans_id mismatch"), "detail must name trans_id, got: {detail}");
        }
        other => panic!("Expected BackendError (trans_id mismatch), got {:?}", other),
    }
}

/// SV-03: a validly signed response whose recip_nonce does not equal the
/// request's sender_nonce must be rejected (replay of another exchange).
#[tokio::test]
async fn ca_backend_rejects_recip_nonce_mismatch() {
    match replay_setup(|h| {
        h.recip_nonce = Some(OctetString::new(rand_bytes(16)).unwrap());
    })
    .await
    {
        Err(ResourceError::BackendError { detail }) => {
            assert!(
                detail.contains("recip_nonce mismatch"),
                "detail must name recip_nonce, got: {detail}"
            );
        }
        other => panic!("Expected BackendError (recip_nonce mismatch), got {:?}", other),
    }
}
