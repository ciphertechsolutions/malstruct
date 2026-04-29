import os
import re

import pytest

import malstruct
from malstruct import (
    Base64,
    Byte,
    Bytes,
    BytesTerminated,
    Container,
    CString,
    Delimited,
    GreedyBytes,
    GreedyString,
    Int32ul,
    Optional,
    Pass,
    Regex,
    RegexMatch,
    RegexSearch,
    StreamError,
    String,
    Stripped,
    Struct,
    Tell,
    this,
)


def test_delimited():
    spec = Delimited(
        b"|",
        "first" / CString(),
        "second" / Int32ul,
        "third" / GreedyBytes,
        "fourth" / Byte,
    )
    assert spec.parse(
        b"Hello\x00\x00|\x01\x00\x00\x00|world!!\x01\x02|\xff"
    ) == Container(first="Hello", second=1, third=b"world!!\x01\x02", fourth=255)
    assert (
        spec.build(dict(first="Hello", second=1, third=b"world!!\x01\x02", fourth=255))
        == b"Hello\x00|\x01\x00\x00\x00|world!!\x01\x02|\xff"
    )

    spec = Delimited(
        b"|", "first" / CString(), "second" / Int32ul, Pass, "fourth" / Byte
    )
    assert spec.parse(
        b"Hello\x00\x00|\x01\x00\x00\x00|world!!\x01\x02|\xff"
    ) == Container(first="Hello", second=1, fourth=255)

    spec = Delimited(
        b"|", "first" / CString(), "second" / Pass, "third" / Optional(Int32ul)
    )
    assert spec.parse(b"Hello\x00\x00|dont care|\x01\x00\x00\x00") == Container(
        first="Hello", second=None, third=1
    )
    assert spec.parse(b"Hello\x00\x00||") == Container(
        first="Hello", second=None, third=None
    )

    spec = Delimited(
        b"YOYO",
        "first" / CString(),
        "second" / Int32ul,
        "third" / GreedyBytes,
        "fourth" / Byte,
    )
    assert spec.parse(
        b"Hello\x00\x00YOYO\x01\x00\x00\x00YOYOworld!!YO!!\x01\x02YOYO\xff"
    ) == Container(first="Hello", second=1, third=b"world!!YO!!\x01\x02", fourth=255)
    assert (
        spec.build(
            dict(first="Hello", second=1, third=b"world!!YO!!\x01\x02", fourth=255)
        )
        == b"Hello\x00YOYO\x01\x00\x00\x00YOYOworld!!YO!!\x01\x02YOYO\xff"
    )


def test_regex():
    ptn = re.compile(
        b"\x01\x02(?P<size>.{4})\x03\x04(?P<path>[A-Za-z].*\x00)", re.DOTALL
    )
    data = b"GARBAGE!\x01\x02\x0a\x00\x00\x00\x03\x04C:\\Windows\x00MORE GARBAGE!"

    assert Regex(ptn, size=Int32ul, path=CString()).parse(data) == Container(
        path="C:\\Windows", size=10
    )

    assert Regex(ptn).parse(data) == Container(
        path=b"C:\\Windows\x00", size=b"\n\x00\x00\x00"
    )

    spec = Struct(
        "re" / Regex(ptn, size=Int32ul, path=CString()),
        "after_re" / Tell,
        "garbage" / GreedyBytes,
    )
    assert spec.parse(data) == Container(
        re=Container(path="C:\\Windows", size=10), after_re=27, garbage=b"MORE GARBAGE!"
    )

    spec = Struct(
        *Regex(ptn, size=Int32ul, path=CString()),
        "after_re" / Tell,
        "garbage" / GreedyBytes,
    )
    assert spec.parse(data) == Container(
        size=10, path="C:\\Windows", after_re=27, garbage=b"MORE GARBAGE!"
    )

    spec = Struct(RegexSearch(b"TRIGGER"), "greeting" / CString())
    assert spec.parse(b"\x01\x02\x04GARBAGE\x05TRIGGERhello world\x00") == Container(
        greeting="hello world"
    )

    assert Regex(b"hello (?P<anchor>)world(?P<extra_data>.*)", anchor=Tell).parse(
        b"hello world!!!!"
    ) == Container(extra_data=b"!!!!", anchor=6)

    assert RegexMatch("hello").parse(b"hello world!") == b"hello"


def test_bytes_terminated():
    assert BytesTerminated(GreedyBytes, term=b"TERM").parse(b"helloTERM") == b"hello"


def test_stripped():
    assert Stripped(GreedyBytes).parse(b"hello\x00\x00\x00") == b"hello"
    assert Stripped(Bytes(10)).parse(b"hello\x00\x00\x00\x00\x00") == b"hello"
    assert Stripped(Bytes(14), pad=b"PAD").parse(b"helloPADPADPAD") == b"hello"
    assert Stripped(Bytes(14), pad=b"PAD").build(b"hello") == b"helloPADPADPAD"
    assert Stripped(CString(), pad="PAD").parse(b"helloPADPAD\x00") == "hello"
    assert Stripped(String(14), pad="PAD").parse(b"helloPADPAD\x00\x00\x00") == "hello"

    assert Stripped(Bytes(13), pad=b"PAD").parse(b"helloPADPADPA") == b"helloPADPADPA"

    with pytest.raises(StreamError):
        Stripped(Bytes(13), pad=b"PAD").build(b"hello")

    assert Stripped(CString(), pad="PAD").build("hello") == b"hello\x00"


def test_base64():
    assert Base64(GreedyString()).build(b"hello") == b"aGVsbG8="

    spec = Base64(
        String(16),
        custom_alpha=b"EFGHQRSTUVWefghijklmnopIJKLMNOPABCDqrstuvwxyXYZabcdz0123456789+/=",
    )
    assert spec.build("hello world") == b"LSoXMS8BO29dMSj="
    assert spec.parse(b"LSoXMS8BO29dMSj=") == b"hello world"

    spec = Base64(CString("utf-16le"))
    data = b"Y\x00W\x00J\x00j\x00Z\x00A\x00=\x00=\x00\x00\x00"
    assert spec.parse(data) == b"abcd"
    assert spec.build(b"abcd") == data

    spec = Base64(CString("utf-8"))
    data = b"YWJjZA==\x00"
    assert spec.parse(data) == b"abcd"
    assert spec.build(b"abcd") == data


def test_iter():
    spec = malstruct.Struct(
        "types" / malstruct.Byte[3],
        "entries"
        / malstruct.Iter(
            this.types,
            {1: malstruct.Int32ul, 2: malstruct.Int16ul},
            default=malstruct.Pass,
        ),
    )
    result = spec.parse(b"\x01\x02\x09\x03\x03\x03\x03\x06\x06")
    assert result == Container(
        types=malstruct.ListContainer([1, 2, 9]),
        entries=malstruct.ListContainer([50529027, 1542, None]),
    )
    assert spec.build(result) == b"\x01\x02\x09\x03\x03\x03\x03\x06\x06"
    assert spec.sizeof(**result) == 9

    spec = malstruct.Struct(
        "sizes" / malstruct.Int16ul[4],
        "entries"
        / malstruct.Iter(
            this.sizes, malstruct.Bytes
        ),  # equivalent to Iter(this.sizes, lambda size: Bytes(size))
    )

    result = spec.parse(b"\x01\x00\x03\x00\x00\x00\x05\x00abbbddddd")
    assert result == Container(
        sizes=malstruct.ListContainer([1, 3, 0, 5]),
        entries=malstruct.ListContainer([b"a", b"bbb", b"", b"ddddd"]),
    )
    assert spec.build(result) == b"\x01\x00\x03\x00\x00\x00\x05\x00abbbddddd"
    assert spec.sizeof(**result) == 17

    assert malstruct.Iter(this.sizes, malstruct.Bytes).sizeof(sizes=[1, 2, 3, 0]) == 6


def test_backwards():
    assert (Bytes(14) >> malstruct.Backwards(Int32ul) >> Tell).parse(
        b"junk stuff\x01\x02\x00\x00"
    ) == malstruct.ListContainer([b"junk stuff\x01\x02\x00\x00", 513, 10])

    spec = Struct(
        malstruct.Seek(0, os.SEEK_END),
        "name" / malstruct.Backwards(String(9)),
        "number" / malstruct.Backwards(Int32ul),
    )
    assert spec.parse(b"A BUNCH OF JUNK DATA\x01\x00\x00\x00joe shmoe") == Container(
        name="joe shmoe", number=1
    )

    with pytest.raises(malstruct.SizeofError):
        spec = Struct(
            malstruct.Seek(0, os.SEEK_END),
            "name" / malstruct.Backwards(CString()),
            "number" / malstruct.Backwards(Int32ul),
        )
        spec.parse(b"A BUNCH OF JUNK DATA\x01\x00\x00\x00joe shmoe\x00")

    spec = Struct(
        malstruct.Seek(0, os.SEEK_END),
        "name" / malstruct.Backwards(String(9)),
        "rest" / malstruct.Backwards(GreedyBytes),
    )
    assert spec.parse(b"A BUNCH OF JUNK DATA\x01\x00\x00\x00joe shmoe") == Container(
        name="joe shmoe", rest=b"A BUNCH OF JUNK DATA\x01\x00\x00\x00"
    )

    spec = Struct(
        malstruct.Seek(0, os.SEEK_END),
        "name" / malstruct.Backwards(String(9)),
        "rest" / malstruct.Backwards(GreedyString(encoding="utf-16le")),
    )
    assert spec.parse(b"h\x00e\x00l\x00l\x00o\x00joe shmoe") == Container(
        name="joe shmoe", rest="hello"
    )

    with pytest.raises(malstruct.FormatFieldError):
        (malstruct.Seek(0, os.SEEK_END) >> malstruct.Backwards(String(10))).parse(b"yo")
