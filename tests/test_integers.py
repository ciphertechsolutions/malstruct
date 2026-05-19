import malstruct


def test_varint_b():
    assert malstruct.VarIntb.parse(b"\x81\xa4\x00") == 20992
    assert malstruct.VarIntb.build(20992) == b"\x81\xa4\x00"


def test_varint_l():
    data = b"\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x10"
    assert malstruct.VarIntl.parse(data) == 2**123
    assert malstruct.VarIntl.build(2**123) == data
