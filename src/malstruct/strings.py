import codecs
import string

from .bytes_ import GreedyBytes
from .core import Adapter, Validator
from .exceptions import *
from .transforms import FixedSized, NullStripped, NullTerminated, Prefixed

#: Explicitly supported encodings (by PaddedString and CString classes).
#:
possiblestringencodings = dict(
    ascii=1,
    utf8=1,
    utf_8=1,
    u8=1,
    utf16=2,
    utf_16=2,
    u16=2,
    utf_16_be=2,
    utf_16_le=2,
    utf32=4,
    utf_32=4,
    u32=4,
    utf_32_be=4,
    utf_32_le=4,
)


def encodingunit(encoding):
    r"""
    >>> encodingunit('utf-8')
    b'\x00'
    >>> encodingunit('utf-16le')
    b'\x00\x00'
    >>> encodingunit('utf-16')
    b'\x00\x00'
    >>> encodingunit('utf-32')
    b'\x00\x00\x00\x00'
    >>> encodingunit('cp950')
    b'\x00'
    """
    _BOM_BYTES = (
        codecs.BOM_UTF32_LE,
        codecs.BOM_UTF32_BE,
        codecs.BOM_UTF16_LE,
        codecs.BOM_UTF16_BE,
        codecs.BOM_UTF8,
    )
    # Check "basic" byte size without BOM mark
    encoding = encoding.lower()
    encoded = "\0".encode(encoding)
    for bom_bytes in _BOM_BYTES:
        if encoded.startswith(bom_bytes) and len(bom_bytes) < len(encoded):
            encoded = encoded[len(bom_bytes) :]
            break
    return bytes(len(encoded))


class StringEncoded(Adapter):
    """Used internally."""

    def __init__(self, subcon, encoding):
        super().__init__(subcon)
        if not encoding:
            raise StringError("String* classes require explicit encoding")
        self.encoding = encoding

    def _decode(self, obj, context, path):
        try:
            return obj.decode(self.encoding)
        except UnicodeDecodeError as e:
            raise StringError(f"[{path}] string decoding failed: {e}")
        except:
            raise StringError(
                f"cannot use encoding {self.encoding!r} to decode {obj!r}"
            )

    def _encode(self, obj, context, path):
        if not isinstance(obj, str):
            raise StringError(
                "string encoding failed, expected unicode string", path=path
            )
        if obj == "":
            return b""
        try:
            return obj.encode(self.encoding)
        except:
            raise StringError(
                f"cannot use encoding {self.encoding!r} to encode {obj!r}"
            )


def PaddedString(length, encoding="utf-8"):
    r"""
    Configurable, fixed-length or variable-length string field.

    When parsing, the byte string is stripped of null bytes (per encoding unit), then decoded. Length is an integer or context lambda. When building, the string is encoded and then padded to specified length. If encoded string is larger than the specified length, it fails with PaddingError. Size is same as length parameter.

    .. warning:: PaddedString and CString only support encodings explicitly listed in :class:`~malstruct.core.possiblestringencodings` .

    :param length: integer or context lambda, length in bytes (not unicode characters)
    :param encoding: string like: utf8 utf16 utf32 ascii

    :raises StringError: building a non-unicode string
    :raises StringError: selected encoding is not on supported list

    Can propagate any exception from the lambda, possibly non-ConstructError.

    Example::

        >>> d = PaddedString(10, "utf8")
        >>> d.build(u"Афон")
        b'\xd0\x90\xd1\x84\xd0\xbe\xd0\xbd\x00\x00'
        >>> d.parse(_)
        u'Афон'
    """
    return StringEncoded(
        FixedSized(length, NullStripped(GreedyBytes, pad=encodingunit(encoding))),
        encoding,
    )


def PascalString(lengthfield, encoding):
    r"""
    Length-prefixed string. The length field can be variable length (such as VarInt) or fixed length (such as Int64ub). :class:`~malstruct.core.VarInt` is recommended when designing new protocols. Stored length is in bytes, not characters. Size is not defined.

    :param lengthfield: Construct instance, field used to parse and build the length (like VarInt Int64ub)
    :param encoding: string like: utf8 utf16 utf32 ascii

    :raises StringError: building a non-unicode string

    Example::

        >>> d = PascalString(VarInt, "utf8")
        >>> d.build(u"Афон")
        b'\x08\xd0\x90\xd1\x84\xd0\xbe\xd0\xbd'
        >>> d.parse(_)
        u'Афон'
    """
    return StringEncoded(Prefixed(lengthfield, GreedyBytes), encoding)


# Alias for original 2.8 name
# FIXME: String() should not remove the null padding!
String = PaddedString


def CString(encoding="utf-8"):
    r"""
    String ending in a terminating null byte (or null bytes in case of UTF16 UTF32).

    .. warning:: String and CString only support encodings explicitly listed in :class:`~malstruct.core.possiblestringencodings` .

    :param encoding: string like: utf8 utf16 utf32 ascii

    :raises StringError: building a non-unicode string
    :raises StringError: selected encoding is not on supported list

    Example::

        >>> d = CString("utf8")
        >>> d.build(u"Афон")
        b'\xd0\x90\xd1\x84\xd0\xbe\xd0\xbd\x00'
        >>> d.parse(_)
        u'Афон'
    """
    return StringEncoded(
        NullTerminated(GreedyBytes, term=encodingunit(encoding)), encoding
    )


def GreedyString(encoding="utf-8"):
    r"""
    String that reads entire stream until EOF, and writes a given string as-is. Analog to :class:`~malstruct.core.GreedyBytes` but also applies unicode-to-bytes encoding.

    :param encoding: string like: utf8 utf16 utf32 ascii

    :raises StringError: building a non-unicode string
    :raises StreamError: stream failed when reading until EOF

    Example::

        >>> d = GreedyString("utf8")
        >>> d.build(u"Афон")
        b'\xd0\x90\xd1\x84\xd0\xbe\xd0\xbd'
        >>> d.parse(_)
        u'Афон'
    """
    return StringEncoded(GreedyBytes, encoding)


def String16(length):
    r"""
    Creates UTF-16 (little endian) encoded string.

    >>> String16(10).build(u'hello')
    b'h\x00e\x00l\x00l\x00o\x00'
    >>> String16(10).parse(b'h\x00e\x00l\x00l\x00o\x00')
    'hello'
    >>> String16(16).parse(b'h\x00e\x00l\x00l\x00o\x00\x00\x00\x00\x00\x00\x00')
    'hello'
    """
    return String(length, encoding="utf-16-le")


def String32(length):
    r"""
    Creates UTF-32 (little endian) encoded string.

    >>> String32(20).build(u'hello')
    b'h\x00\x00\x00e\x00\x00\x00l\x00\x00\x00l\x00\x00\x00o\x00\x00\x00'
    >>> String32(20).parse(b'h\x00\x00\x00e\x00\x00\x00l\x00\x00\x00l\x00\x00\x00o\x00\x00\x00')
    'hello'
    """
    return String(length, encoding="utf-32-le")


class Printable(Validator):
    r"""
    Validator used to validate that a parsed String (or Bytes) is a printable (ascii) string.

    NOTE: A ValidationError is a type of ConstructError and will be cause if catching ConstructError.

    >>> Printable(String(5)).parse(b'hello')
    'hello'
    >>> Printable(String(5)).parse(b'he\x11o!')
    Traceback (most recent call last):
        ...
    construct.core.ValidationError: Error in path (parsing)
    object failed validation: heo!
    >>> Printable(Bytes(3)).parse(b'\x01NO')
    Traceback (most recent call last):
        ...
    construct.core.ValidationError: Error in path (parsing)
    object failed validation: b'\x01NO'
    >>> Printable(Bytes(3)).parse(b'YES')
    b'YES'
    """

    def _validate(self, obj, context, path):
        if isinstance(obj, bytes):
            return all(chr(byte) in string.printable for byte in obj)
        return isinstance(obj, str) and all(char in string.printable for char in obj)
