from malstruct import Const, Container, CString, Int16ul, Struct, chunk, find_constructs


def test_find_constructs():
    spec = Struct(Const(b"MZ"), "int" / Int16ul, "string" / CString())
    assert list(
        find_constructs(
            spec, b"\x01\x02\x03MZ\x0a\x00hello\x00\x03\x04MZ\x0b\x00world\x00\x00"
        )
    ) == [
        (3, Container(int=10, string="hello")),
        (15, Container(int=11, string="world")),
    ]
    assert list(find_constructs(spec, b"nope")) == []


def test_chunk():
    assert list(chunk("hello", 2)) == [("h", "e"), ("l", "l")]
    assert list(chunk("hello!", 2)) == [("h", "e"), ("l", "l"), ("o", "!")]
