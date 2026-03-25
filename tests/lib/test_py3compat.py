from tests.declarativeunittest import *
from malstruct.lib.py3compat import *


def test_int_byte():
    assert int2byte(5) == b"\x05"
    assert int2byte(255) == b"\xff"
    assert byte2int(b"\x05") == 5
    assert byte2int(b"\xff") == 255
    assert all(byte2int(int2byte(i)) == i for i in range(256))

def test_str_bytes():
    assert str2bytes("abc") == b"abc"
    assert bytes2str(b"abc") == "abc"
    assert bytes2str(str2bytes("abc123\n")) == "abc123\n"
    assert str2bytes(bytes2str(b"abc123\n")) == b"abc123\n"
