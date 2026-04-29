from malstruct import Boolean, CString, Int32ul


def test_boolean():
    assert Boolean(Int32ul).parse(b"\x01\x02\x03\x04") == True
    assert Boolean(Int32ul).parse(b"\x00\x00\x00\x00") == False
    assert Boolean(CString()).parse(b"hello\x00") == True
    assert Boolean(CString()).parse(b"\x00") == False
