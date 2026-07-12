from resolver_identity.wrapper.dns_message import make_servfail


def test_make_servfail_preserves_id_and_question_count():
    query = bytes.fromhex("123401000001000000000000") + b"\x07example\x03com\x00\x00\x01\x00\x01"
    response = make_servfail(query)
    assert response[:2] == b"\x12\x34"
    assert response[3] & 0x0F == 2
    assert response[4:6] == b"\x00\x01"
