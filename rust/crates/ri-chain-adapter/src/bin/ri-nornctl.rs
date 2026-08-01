use std::env;
use std::time::Duration;

use ri_chain_adapter::{NornClientTlsMaterial, NornDevelopmentClient};
use serde_json::json;

type AnyError = Box<dyn std::error::Error + Send + Sync>;

#[tokio::main]
async fn main() -> Result<(), AnyError> {
    let mut arguments = env::args().skip(1);
    let url = arguments.next().ok_or(usage())?;
    let command = arguments.next().ok_or(usage())?;
    let client = match nornctl_tls_material()? {
        Some(material) => NornDevelopmentClient::new_with_tls(
            url,
            Duration::from_secs(10),
            16 * 1024 * 1024,
            material,
        )?,
        None => NornDevelopmentClient::new(url, Duration::from_secs(10), 16 * 1024 * 1024)?,
    };
    match command.as_str() {
        "head" => {
            println!("{}", json!({ "head": client.head().await? }));
        }
        "block" => {
            let number = arguments.next().ok_or(usage())?.parse()?;
            let block = client.block(number).await?;
            println!("{}", serde_json::to_string(&block)?);
        }
        "transactions" => {
            let number = arguments.next().ok_or(usage())?.parse()?;
            println!(
                "{}",
                serde_json::to_string(&client.transactions(number).await?)?
            );
        }
        "read" => {
            let address = arguments.next().ok_or(usage())?;
            let key = arguments.next().ok_or(usage())?;
            print!("{}", client.read(&address, &key).await?);
        }
        _ => return Err(usage().into()),
    }
    Ok(())
}

fn nornctl_tls_material() -> Result<Option<NornClientTlsMaterial>, AnyError> {
    let variables = [
        "RI_NORNCTL_TLS_CA_FILE",
        "RI_NORNCTL_TLS_CLIENT_CERT_FILE",
        "RI_NORNCTL_TLS_CLIENT_KEY_FILE",
    ];
    let paths = variables
        .iter()
        .map(|name| env::var(name).ok().filter(|value| !value.trim().is_empty()))
        .collect::<Vec<_>>();
    if paths.iter().all(Option::is_none) {
        return Ok(None);
    }
    if paths.iter().any(Option::is_none) {
        return Err(format!("{} must be configured together", variables.join(", ")).into());
    }
    Ok(Some(NornClientTlsMaterial {
        ca_certificate_pem: std::fs::read(paths[0].as_deref().unwrap_or_default())?,
        client_certificate_pem: std::fs::read(paths[1].as_deref().unwrap_or_default())?,
        client_private_key_pem: std::fs::read(paths[2].as_deref().unwrap_or_default())?,
    }))
}

fn usage() -> &'static str {
    concat!(
        "usage: ri-nornctl <grpc-url> head\n",
        "       ri-nornctl <grpc-url> block <height>\n",
        "       ri-nornctl <grpc-url> transactions <height>\n",
        "       ri-nornctl <grpc-url> read <address> <key>"
    )
}
