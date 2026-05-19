import malstruct
from malstruct import DateTimeDateData, EpochTimeUTC


def test_datetime_datedata():
    assert (
        DateTimeDateData.parse(b"\x80\xb4N3\xd1\xd4\xd1H") == "2014-11-23 01:09:01 UTC"
    )


def test_epoch_time():
    assert EpochTimeUTC.parse(b"\xff\x93\x37\x57") == "2016-05-14T21:09:19+00:00"


def test_hex_string():
    assert malstruct.HexString(malstruct.Int32ul).build("0x123") == b"#\x01\x00\x00"
    assert malstruct.HexString(malstruct.Int32ul).parse(b"\x20\x01\x00\x00") == "0x120"
    assert malstruct.HexString(malstruct.Int16ub).parse(b"\x12\x34") == "0x1234"
    assert (
        malstruct.HexString(malstruct.BytesInteger(20)).parse(b"\x01" * 20)
        == "0x101010101010101010101010101010101010101"
    )


def test_uuid():
    value = "{12345678-1234-5678-1234-567812345678}"

    assert malstruct.UUID().build(value) == b"xV4\x124\x12xV\x124Vx\x124Vx"
    assert malstruct.UUID(le=False).build(value) == b"\x124Vx\x124Vx\x124Vx\x124Vx"
    assert malstruct.UUID().parse(b"xV4\x124\x12xV\x124Vx\x124Vx") == value
    assert malstruct.UUID(le=False).parse(b"\x124Vx\x124Vx\x124Vx\x124Vx") == value
