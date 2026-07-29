use serde_json::json;

use ri_core::{canonical_json_text, object_hash, resolver_id_key, sign_ed25519, verify_ed25519};

const PRIVATE_KEY_B64: &str = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=";
const PUBLIC_KEY_B64: &str = "A6EHv/POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg=";

#[test]
fn canonical_json_and_hash_match_python_v1() {
    let value = json!({
        "schema_version": "resolver-auth-object-v1",
        "resolver_id": "operator/测试-r1",
        "object_version": 7,
        "active": true,
        "endpoints": [{
            "transport": "udp",
            "port": 53,
            "ip": "192.0.2.53",
            "signature": "nested-ignored"
        }],
        "metadata": {"z": null, "a": "é"},
        "signature": "outer-ignored"
    });
    assert_eq!(
        canonical_json_text(&value).unwrap(),
        "{\"active\":true,\"endpoints\":[{\"ip\":\"192.0.2.53\",\"port\":53,\"transport\":\"udp\"}],\"metadata\":{\"a\":\"é\",\"z\":null},\"object_version\":7,\"resolver_id\":\"operator/测试-r1\",\"schema_version\":\"resolver-auth-object-v1\"}"
    );
    assert_eq!(
        object_hash(&value).unwrap(),
        "0xe1758c780a63d252e679e7c6d805deca901e212395966aff8d84328d061de1c5"
    );
    assert_eq!(
        resolver_id_key("operator/测试-r1"),
        "0x6ec545be9efc9a98709baf3424d3cf3910a951c6c004672de349ff4b3a4e3891"
    );
}

#[test]
fn ed25519_signature_matches_python_v1() {
    let mut value = json!({
        "schema_version": "resolver-auth-object-v1",
        "resolver_id": "operator/测试-r1",
        "object_version": 7,
        "active": true,
        "endpoints": [{"transport": "udp", "port": 53, "ip": "192.0.2.53"}],
        "metadata": {"z": null, "a": "é"}
    });
    let signature = sign_ed25519(&value, PRIVATE_KEY_B64).unwrap();
    assert_eq!(
        signature,
        "base64:ed25519:1Pki8tBUR6lC7bu3h+O6spXcEoCobmcUuHTfeKBor8kRSIjtD8OO0XAgNGKRaVDiTWu9e+5eI9HVq05v/3MfCg=="
    );
    value["signature"] = signature.into();
    verify_ed25519(&value, PUBLIC_KEY_B64).unwrap();
}
