from malstruct import DotNetNullString, DotNetSigToken, DotNetUInt


def test_dotnet_uint():
    assert DotNetUInt.build(16) == b"\x10"
    assert DotNetUInt.parse(b"\x10") == 16
    assert DotNetUInt.build(256) == b"\x81\x00"
    assert DotNetUInt.parse(b"\x81\x00") == 256
    assert DotNetUInt.build(0xFFFF) == b"\xc0\x00\xff\xff"
    assert DotNetUInt.parse(b"\xc0\x00\xff\xff") == 0xFFFF


def test_dotnet_null_string():
    assert DotNetNullString.parse(b"\xff") is None
    assert DotNetNullString.build(None) == b"\xff"


def test_dotnet_sig_token():
    assert DotNetSigToken.parse(b"\x81\x42") == 452984912
    assert DotNetSigToken.build(0x01000002) == b"\t"
