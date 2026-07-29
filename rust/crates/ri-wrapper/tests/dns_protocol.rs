use ri_wrapper::{DnsTransport, make_servfail, parse_upstream, valid_response, validate_query};

fn query() -> Vec<u8> {
    vec![
        0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, b'e', b'x',
        b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00, 0x00, 0x01, 0x00, 0x01,
    ]
}

fn response() -> Vec<u8> {
    let mut response = query();
    response[2] |= 0x80;
    response
}

#[test]
fn servfail_keeps_id_and_question_but_clears_answer_sections() {
    let query = query();
    let response = make_servfail(&query);
    assert_eq!(&response[..2], &[0x12, 0x34]);
    assert_ne!(response[2] & 0x80, 0);
    assert_eq!(response[3] & 0x0f, 2);
    assert_eq!(&response[4..6], &[0, 1]);
    assert_eq!(&response[6..12], &[0; 6]);
}

#[test]
fn rejects_short_response_wrong_id_and_missing_qr() {
    let query = query();
    assert!(!valid_response(&query, &[0; 11]));
    let mut response = query.clone();
    response[2] |= 0x80;
    response[0] = 0xff;
    assert!(!valid_response(&query, &response));
    response[0] = query[0];
    assert!(valid_response(&query, &response));
}

#[test]
fn rejects_response_with_different_question_or_compression_loop() {
    let query = query();
    let mut different = response();
    different[13] = b'x';
    assert!(!valid_response(&query, &different));

    let mut looped = response();
    looped[12] = 0xc0;
    looped[13] = 0x0c;
    assert!(!valid_response(&query, &looped));
}

#[test]
fn validates_queries_and_parses_numeric_upstreams() {
    validate_query(&query()).unwrap();
    assert!(validate_query(&[0; 11]).is_err());
    let upstream = parse_upstream("tcp://192.0.2.53:53").unwrap();
    assert_eq!(upstream.transport, DnsTransport::Tcp);
    assert_eq!(upstream.address.to_string(), "192.0.2.53:53");
    assert!(parse_upstream("https://resolver.example:443").is_err());
}
