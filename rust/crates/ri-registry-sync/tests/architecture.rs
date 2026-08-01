use std::fs;
use std::path::Path;

fn read_tree(path: &Path) -> String {
    let mut combined = String::new();
    for entry in fs::read_dir(path).unwrap() {
        let entry = entry.unwrap();
        let path = entry.path();
        if path.is_dir() {
            combined.push_str(&read_tree(&path));
        } else if path.extension().is_some_and(|extension| extension == "rs") {
            combined.push_str(&fs::read_to_string(path).unwrap());
        }
    }
    combined
}

#[test]
fn wrapper_and_agent_cannot_access_chain_adapters_or_rpc_configuration() {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    for crate_name in ["ri-agent", "ri-wrapper"] {
        let crate_path = manifest.parent().unwrap().join(crate_name);
        let cargo = fs::read_to_string(crate_path.join("Cargo.toml")).unwrap();
        let source = read_tree(&crate_path.join("src"));
        assert!(!cargo.contains("ri-chain-adapter"), "{crate_name}");
        assert!(!source.contains("RegistryChainAdapter"), "{crate_name}");
        assert!(!source.contains("RI_CHAIN_"), "{crate_name}");
        assert!(!source.contains("RI_WEB3_RPC_URL"), "{crate_name}");
    }
}
