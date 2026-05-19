import malstruct


def test_system_time():
    data = b"\xdd\x07\t\x00\x03\x00\x12\x00\t\x00.\x00\x15\x00\xf2\x02"
    assert malstruct.SystemTime.parse(data) == "2013-09-18T09:46:21.754000"
    assert malstruct.SystemTimeUTC.parse(data) == "2013-09-18T09:46:21.754000+00:00"


def test_file_time():
    assert (
        malstruct.FileTimeUTC.parse(b"\x00\x93\xcc\x11\xa7\x88\xd0\x01")
        == "2015-05-07T09:20:33.328000+00:00"
    )


def test_sockaddr():
    data = b"\x02\x00\x50\x00\x7f\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00"
    assert malstruct.SOCKADDR_IN.parse(data) == malstruct.Container(
        sin_family=2,
        sin_port=20480,
        sin_addr="127.0.0.1",
        sin_zero=b"\x00\x00\x00\x00\x00\x00\x00\x00",
    )
    assert malstruct.SOCKADDR_IN_L.parse(data) == malstruct.Container(
        sin_family=2,
        sin_port=80,
        sin_addr="127.0.0.1",
        sin_zero=b"\x00\x00\x00\x00\x00\x00\x00\x00",
    )
