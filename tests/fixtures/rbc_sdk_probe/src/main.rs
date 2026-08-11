use rbc::{Config, GetResourceRequest, ProviderRawConfig, ProviderType};
use serde_json::{json, Map, Value};

fn provider(provider_type: ProviderType, config_path: &str) -> ProviderRawConfig {
    let mut rest = Map::new();
    rest.insert("config_path".to_string(), Value::String(config_path.to_string()));
    ProviderRawConfig { provider_type, enabled: true, rest }
}

fn run() -> Result<Value, Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let base_url = args.next().ok_or("missing base URL")?;
    let agent_config = args.next().ok_or("missing agent config")?;
    let resource_uri = args.next().ok_or("missing resource URI")?;

    let config = Config::builder()
        .base_url(&base_url)
        .timeout_secs(30)
        .evidence_provider(vec![provider(ProviderType::Native, &agent_config)])
        .token_provider(vec![provider(ProviderType::Rbs, &agent_config)])
        .build()?;
    let client = rbc::Client::new(config)?;
    let challenge = client.get_auth_challenge()?;
    let session = client.new_session(None)?;
    let evidence = session.collect_evidence(&challenge)?;
    let token = session.attest(Some(&evidence))?.token;
    let resource = session.get_resource(&resource_uri, GetResourceRequest::ByAttestToken(&token))?;
    let jwe = std::str::from_utf8(&resource.content)?;
    let plaintext = session.decrypt_content(jwe, None, None)?;

    Ok(json!({
        "nonce": challenge.nonce,
        "attester_type": evidence["measurements"][0]["evidences"][0]["attester_type"],
        "token_segments": token.split('.').count(),
        "uri": resource.uri,
        "content_type": resource.content_type,
        "plaintext": serde_json::from_slice::<Value>(&plaintext)?,
    }))
}

fn main() {
    match run() {
        Ok(output) => println!("{output}"),
        Err(error) => {
            eprintln!("rbc SDK probe failed: {error}");
            std::process::exit(1);
        },
    }
}

