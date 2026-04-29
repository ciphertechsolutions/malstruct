from malstruct import IP4Address, MacAddress


def test_mac_address():
    assert MacAddress.parse(b"\x00\x0c\x29\xd3\x91\xbc") == "00-0c-29-d3-91-bc"


def test_ip_address():
    assert IP4Address.parse(b"\x01\x02\x03\x04") == "1.2.3.4"
