import malstruct
from malstruct import this


def test_zlib():
    assert (
        malstruct.ZLIB(malstruct.Bytes(12)).build(b"data")
        == b"x\x9cKI,I\x04\x00\x04\x00\x01\x9b"
    )
    assert (
        malstruct.ZLIB(malstruct.GreedyBytes, level=0).build(b"data")
        == b"x\x01\x01\x04\x00\xfb\xffdata\x04\x00\x01\x9b"
    )
    assert (
        malstruct.ZLIB(malstruct.GreedyBytes).parse(b"x^KI,I\x04\x00\x04\x00\x01\x9b")
        == b"data"
    )


def test_focuslast():
    assert (
        malstruct.FocusLast(malstruct.Byte, malstruct.Byte, malstruct.String(2)).parse(
            b"\x01\x02hi"
        )
        == "hi"
    )

    spec = malstruct.FocusLast(
        "a" / malstruct.Byte, "b" / malstruct.Byte, malstruct.String(this.a + this.b)
    )
    assert spec.parse(b"\x01\x02hi!") == "hi!"
    assert spec.build("hi!", a=1, b=2) == b"\x01\x02hi!"
