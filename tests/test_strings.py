import pytest

from malstruct import Bytes, Printable, String, String16, String32, ValidationError


def test_string16():
    assert String16(10).build("hello") == b"h\x00e\x00l\x00l\x00o\x00"
    assert String16(10).parse(b"h\x00e\x00l\x00l\x00o\x00") == "hello"
    assert (
        String16(16).parse(b"h\x00e\x00l\x00l\x00o\x00\x00\x00\x00\x00\x00\x00")
        == "hello"
    )


def test_string32():
    assert (
        String32(20).build("hello")
        == b"h\x00\x00\x00e\x00\x00\x00l\x00\x00\x00l\x00\x00\x00o\x00\x00\x00"
    )
    assert (
        String32(20).parse(
            b"h\x00\x00\x00e\x00\x00\x00l\x00\x00\x00l\x00\x00\x00o\x00\x00\x00"
        )
        == "hello"
    )


def test_printable():
    assert Printable(String(5)).parse(b"hello") == "hello"
    assert Printable(Bytes(3)).parse(b"YES") == b"YES"
    with pytest.raises(ValidationError):
        Printable(String(5)).parse(b"he\x11o!")
    with pytest.raises(ValidationError):
        Printable(Bytes(3)).parse(b"\x01NO")
