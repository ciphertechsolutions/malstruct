"""Construct helpers for .NET"""

from malstruct.core import Adapter, Construct
from malstruct.exceptions import *
from malstruct.helpers import stream_read, stream_write


class _DotNetUInt(Construct):
    r"""
    DotNet encoded unsigned 32-bit integer, where first byte indicates the length of the integer.

    Example:

        >>> DotNetUInt.build(16)
        '\x10'
        >>> DotNetUInt.parse(_)
        16
        >>> DotNetUInt.build(256)
        '\x81\x00'
        >>> DotNetUInt.parse(_)
        256
        >>> DotNetUInt.build(0xffff)
        '\xc0\x00\xff\xff'
        >>> DotNetUInt.parse(_)
        65535
    """

    def _parse(self, stream, context, path):
        b = int.from_bytes(stream_read(stream, 1), "little")
        if b & 0x80 == 0:
            num = b
        elif b & 0xC0 == 0x80:
            num = ((b & 0x3F) << 8) + int.from_bytes(stream_read(stream, 1), "little")
        elif b & 0xE0 == 0xC0:
            num = (b & 0x1F) << 24
            num += int.from_bytes(stream_read(stream, 1), "little") << 16
            num += int.from_bytes(stream_read(stream, 1), "little") << 8
            num += int.from_bytes(stream_read(stream, 1), "little")
        else:
            raise ConstructError("DotNetUInt encountered an invalid string")
        return num

    def _build(self, obj, stream, context, path):
        if obj < 0:
            raise ConstructError("DotNetUInt cannot build from negative number")
        if obj > 0x1FFFFFFF:
            raise ConstructError("DotNetUInt encountered too large a number")
        if obj < 0x80:
            stream_write(stream, bytes([obj]), 1)
        elif obj < 0x3FFF:
            stream_write(stream, bytes([(obj >> 8) | 0x80]), 1)
            stream_write(stream, bytes([obj & 0xFF]), 1)
        else:
            stream_write(stream, bytes([(obj >> 24) | 0xC0]), 1)
            stream_write(stream, bytes([(obj >> 16) & 0xFF]), 1)
            stream_write(stream, bytes([(obj >> 8) & 0xFF]), 1)
            stream_write(stream, bytes([obj & 0xFF]), 1)


# using the @singleton decorator seems to break our ability to run doctests.
DotNetUInt = _DotNetUInt()


class _DotNetNullString(Construct):
    r"""
    DotNet null string, different from an empty zero-byte string, encoded as a single 0xff byte.

    Example:

        >>> repr(DotNetNullString.parse('\xff'))
        'None'
        >>> DotNetNullString.build(None)
        '\xff'
    """

    def _parse(self, stream, context, path):
        if stream_read(stream, 1) != b"\xff":
            raise ConstructError("DotNetNullString encounted an invalid byte.")
        return None

    def _build(self, obj, stream, context, path):
        stream_write(stream, b"\xff", 1)

    def _sizeof(self, context, path):
        return 1


DotNetNullString = _DotNetNullString()


class _DotNetSigToken(Adapter):
    r"""
    Adapter used to create or read a compressed token used in signatures. The token must be a typedef,
    typeref, or typespec token.

    >>> DotNetSigToken.parse('\x81\x42')
    452984912
    >>> DotNetSigToken.build(0x01000002)
    '\t'
    """

    TOKEN_ENCODE = {
        0x02: 0,
        0x01: 1,
        0x1B: 2,
    }

    def _encode(self, obj, context, path):
        encoded = self.TOKEN_ENCODE.get(obj >> 24, 3)
        if encoded is None:
            raise ConstructError(
                "DotNetSigToken encountered a token other than typedef, typeref, or typespec"
            )
        return ((obj & 0x00FFFFFF) << 2) | encoded

    def _decode(self, obj, context, path):
        if obj & 3 == 3 or obj & 0xFC00000000:
            raise ConstructError(
                "DotNetSigToken encountered an invalid typedef, typeref, or typespec token"
            )
        return (obj >> 2) | [0x02000000, 0x01000000, 0x1B000000][obj & 3]


DotNetSigToken = _DotNetSigToken(DotNetUInt)
