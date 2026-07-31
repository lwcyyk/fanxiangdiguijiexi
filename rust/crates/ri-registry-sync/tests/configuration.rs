use std::process::{Command, Output};

fn run_registry_sync(environment: &[(&str, &str)]) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_ri-registry-sync"));
    command.env_clear().env("RI_ENVIRONMENT", "test");
    for (name, value) in environment {
        command.env(name, value);
    }
    command.output().unwrap()
}

fn error_text(output: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

#[test]
fn missing_chain_adapter_fails_startup() {
    let output = run_registry_sync(&[]);
    assert!(!output.status.success());
    assert!(error_text(&output).contains("RI_CHAIN_ADAPTER is required"));
}

#[test]
fn unknown_chain_adapter_fails_without_fallback() {
    let output = run_registry_sync(&[("RI_CHAIN_ADAPTER", "typo-evm")]);
    assert!(!output.status.success());
    assert!(error_text(&output).contains("unsupported RI_CHAIN_ADAPTER typo-evm"));
}

#[test]
fn conflicting_new_and_legacy_evm_variables_fail_startup() {
    let output = run_registry_sync(&[
        ("RI_CHAIN_ADAPTER", "evm"),
        ("RI_CHAIN_RPC_URL", "https://rpc-a.invalid"),
        ("RI_WEB3_RPC_URL", "https://rpc-b.invalid"),
    ]);
    assert!(!output.status.success());
    let error = error_text(&output);
    assert!(
        error.contains("conflicting compatibility variables"),
        "{error}"
    );
    assert!(error.contains("RI_CHAIN_RPC_URL"), "{error}");
    assert!(error.contains("RI_WEB3_RPC_URL"), "{error}");
}

#[test]
fn selected_adapter_does_not_fallback_to_configured_norn() {
    let output = run_registry_sync(&[
        ("RI_CHAIN_ADAPTER", "evm"),
        (
            "RI_NORN_RPC_URLS",
            "http://127.0.0.1:45555,http://127.0.0.1:45556",
        ),
        ("RI_NORN_GENESIS_BLOCK_HASH", "0x11"),
    ]);
    assert!(!output.status.success());
    let error = error_text(&output);
    assert!(error.contains("RI_CHAIN_RPC_URL"), "{error}");
    assert!(
        !error.contains("Norn Registry Sync target pinned"),
        "{error}"
    );
}

#[test]
fn adapter_specific_required_fields_fail_startup() {
    for adapter in ["evm", "norn", "external"] {
        let output = run_registry_sync(&[("RI_CHAIN_ADAPTER", adapter)]);
        assert!(!output.status.success(), "{adapter} unexpectedly started");
    }
}
