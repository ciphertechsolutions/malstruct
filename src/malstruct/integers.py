"""
Integers and floats
"""

import struct
import sys

from malstruct.lib import (
    bits2integer,
    bytes2integer,
    integer2bits,
    integer2bytes,
    swapbytes,
    swapbytesinbits,
)

from .core import Construct, evaluate
from .exceptions import *
from .helpers import singleton, stream_read, stream_write


class FormatField(Construct):
    r"""
    Field that uses `struct` module to pack and unpack CPU-sized integers and floats and booleans. This is used to implement most Int* Float* fields, but for example cannot pack 24-bit integers, which is left to :class:`~malstruct.core.BytesInteger` class. For booleans I also recommend using Flag class instead.

    See `struct module <https://docs.python.org/3/library/struct.html>`_ documentation for instructions on crafting format strings.

    Parses into an integer or float or boolean. Builds from an integer or float or boolean into specified byte count and endianness. Size is determined by `struct` module according to specified format string.

    :param endianity: string, character like: < > =
    :param format: string, character like: B H L Q b h l q e f d ?

    :raises StreamError: requested reading negative amount, could not read enough bytes, requested writing different amount than actual data, or could not write all bytes
    :raises FormatFieldError: wrong format string, or struct.(un)pack complained about the value

    Example::

        >>> d = FormatField(">", "H") or Int16ub
        >>> d.parse(b"\x01\x00")
        256
        >>> d.build(256)
        b"\x01\x00"
        >>> d.sizeof()
        2
    """

    def __init__(self, endianity, format):
        if endianity not in list("=<>"):
            raise FormatFieldError("endianity must be like: = < >", endianity)
        if format not in list("fdBHLQbhlqe?"):
            raise FormatFieldError(
                "format must be like: B H L Q b h l q e f d ?", format
            )

        super().__init__()
        self.fmtstr = endianity + format
        self.length = struct.calcsize(endianity + format)

    def _parse(self, stream, context, path):
        data = stream_read(stream, self.length, path)
        try:
            return struct.unpack(self.fmtstr, data)[0]
        except Exception:
            raise FormatFieldError(
                "struct %r error during parsing" % self.fmtstr, path=path
            )

    def _build(self, obj, stream, context, path):
        try:
            data = struct.pack(self.fmtstr, obj)
        except Exception:
            raise FormatFieldError(
                "struct {!r} error during building, given value {!r}".format(
                    self.fmtstr, obj
                ),
                path=path,
            )
        stream_write(stream, data, self.length, path)
        return obj

    def _sizeof(self, context, path):
        return self.length


class BytesInteger(Construct):
    r"""
    Field that packs integers of arbitrary size. Int24* fields use this class.

    Parses into an integer. Builds from an integer into specified byte count and endianness. Size is specified in ctor.

    Analog to :class:`~malstruct.core.BitsInteger` which operates on bits. In fact::

        BytesInteger(n) <--> Bitwise(BitsInteger(8*n))
        BitsInteger(8*n) <--> Bytewise(BytesInteger(n))

    Byte ordering refers to bytes (chunks of 8 bits) so, for example::

        BytesInteger(n, swapped=True) <--> Bitwise(BitsInteger(8*n, swapped=True))

    :param length: integer or context lambda, number of bytes in the field
    :param signed: bool, whether the value is signed (two's complement), default is False (unsigned)
    :param swapped: bool or context lambda, whether to swap byte order (little endian), default is False (big endian)

    :raises StreamError: requested reading negative amount, could not read enough bytes, requested writing different amount than actual data, or could not write all bytes
    :raises IntegerError: length is negative or zero
    :raises IntegerError: value is not an integer
    :raises IntegerError: number does not fit given width and signed parameters

    Can propagate any exception from the lambda, possibly non-ConstructError.

    Example::

        >>> d = BytesInteger(4) or Int32ub
        >>> d.parse(b"abcd")
        1633837924
        >>> d.build(1)
        b'\x00\x00\x00\x01'
        >>> d.sizeof()
        4
    """

    def __init__(self, length, signed=False, swapped=False):
        super().__init__()
        self.length = length
        self.signed = signed
        self.swapped = swapped

    def _parse(self, stream, context, path):
        length = evaluate(self.length, context)
        if length <= 0:
            raise IntegerError(f"length {length} must be positive", path=path)
        data = stream_read(stream, length, path)
        if evaluate(self.swapped, context):
            data = swapbytes(data)
        try:
            return bytes2integer(data, self.signed)
        except ValueError as e:
            raise IntegerError(str(e), path=path)

    def _build(self, obj, stream, context, path):
        if not isinstance(obj, int):
            raise IntegerError(f"value {obj} is not an integer", path=path)
        length = evaluate(self.length, context)
        if length <= 0:
            raise IntegerError(f"length {length} must be positive", path=path)
        try:
            data = integer2bytes(obj, length, self.signed)
        except ValueError as e:
            raise IntegerError(str(e), path=path)
        if evaluate(self.swapped, context):
            data = swapbytes(data)
        stream_write(stream, data, length, path)
        return obj

    def _sizeof(self, context, path):
        try:
            return evaluate(self.length, context)
        except (KeyError, AttributeError):
            raise SizeofError(
                "cannot calculate size, key not found in context", path=path
            )


class BitsInteger(Construct):
    r"""
    Field that packs arbitrarily large (or small) integers. Some fields (Bit Nibble Octet) use this class. Must be enclosed in :class:`~malstruct.core.Bitwise` context.

    Parses into an integer. Builds from an integer into specified bit count and endianness. Size (in bits) is specified in ctor.

    Analog to :class:`~malstruct.core.BytesInteger` which operates on bytes. In fact::

        BytesInteger(n) <--> Bitwise(BitsInteger(8*n))
        BitsInteger(8*n) <--> Bytewise(BytesInteger(n))

    Note that little-endianness is only defined for multiples of 8 bits.

    Byte ordering (i.e. `swapped` parameter) refers to bytes (chunks of 8 bits) so, for example::

        BytesInteger(n, swapped=True) <--> Bitwise(BitsInteger(8*n, swapped=True))

    Swapped argument was recently fixed. To obtain previous (faulty) behavior, you can use `ByteSwapped`, `BitsSwapped` and `Bitwise` in whatever particular order (see examples).

    :param length: integer or context lambda, number of bits in the field
    :param signed: bool, whether the value is signed (two's complement), default is False (unsigned)
    :param swapped: bool or context lambda, whether to swap byte order (little endian), default is False (big endian)

    :raises StreamError: requested reading negative amount, could not read enough bytes, requested writing different amount than actual data, or could not write all bytes
    :raises IntegerError: length is negative or zero
    :raises IntegerError: value is not an integer
    :raises IntegerError: number does not fit given width and signed parameters
    :raises IntegerError: little-endianness selected but length is not multiple of 8 bits

    Can propagate any exception from the lambda, possibly non-ConstructError.

    Examples::

        >>> d = Bitwise(BitsInteger(8)) or Bitwise(Octet)
        >>> d.parse(b"\x10")
        16
        >>> d.build(255)
        b'\xff'
        >>> d.sizeof()
        1

    Obtaining other byte or bit orderings::

        >>> d = BitsInteger(2)
        >>> d.parse(b'\x01\x00') # Bit-Level Big-Endian
        2
        >>> d = ByteSwapped(BitsInteger(2))
        >>> d.parse(b'\x01\x00') # Bit-Level Little-Endian
        1
        >>> d = BitsInteger(16) # Byte-Level Big-Endian, Bit-Level Big-Endian
        >>> d.build(5 + 19*256)
        b'\x00\x00\x00\x01\x00\x00\x01\x01\x00\x00\x00\x00\x00\x01\x00\x01'
        >>> d = BitsInteger(16, swapped=True) # Byte-Level Little-Endian, Bit-Level Big-Endian
        >>> d.build(5 + 19*256)
        b'\x00\x00\x00\x00\x00\x01\x00\x01\x00\x00\x00\x01\x00\x00\x01\x01'
        >>> d = ByteSwapped(BitsInteger(16)) # Byte-Level Little-Endian, Bit-Level Little-Endian
        >>> d.build(5 + 19*256)
        b'\x01\x00\x01\x00\x00\x00\x00\x00\x01\x01\x00\x00\x01\x00\x00\x00'
        >>> d = ByteSwapped(BitsInteger(16, swapped=True)) # Byte-Level Big-Endian, Bit-Level Little-Endian
        >>> d.build(5 + 19*256)
        b'\x01\x01\x00\x00\x01\x00\x00\x00\x01\x00\x01\x00\x00\x00\x00\x00'
    """

    def __init__(self, length, signed=False, swapped=False):
        super().__init__()
        self.length = length
        self.signed = signed
        self.swapped = swapped

    def _parse(self, stream, context, path):
        length = evaluate(self.length, context)
        if length <= 0:
            raise IntegerError(f"length {length} must be positive", path=path)
        data = stream_read(stream, length, path)
        try:
            if evaluate(self.swapped, context):
                data = swapbytesinbits(data)
            return bits2integer(data, self.signed)
        except ValueError as e:
            raise IntegerError(str(e), path=path)

    def _build(self, obj, stream, context, path):
        if not isinstance(obj, int):
            raise IntegerError(f"value {obj} is not an integer", path=path)
        length = evaluate(self.length, context)
        if length <= 0:
            raise IntegerError(f"length {length} must be positive", path=path)
        try:
            data = integer2bits(obj, length, self.signed)
            if evaluate(self.swapped, context):
                data = swapbytesinbits(data)
        except ValueError as e:
            raise IntegerError(str(e), path=path)
        stream_write(stream, data, length, path)
        return obj

    def _sizeof(self, context, path):
        try:
            return evaluate(self.length, context)
        except (KeyError, AttributeError):
            raise SizeofError(
                "cannot calculate size, key not found in context", path=path
            )


@singleton
def Bit():
    """A 1-bit integer, must be enclosed in a Bitwise (eg. BitStruct)"""
    return BitsInteger(1)


@singleton
def Nibble():
    """A 4-bit integer, must be enclosed in a Bitwise (eg. BitStruct)"""
    return BitsInteger(4)


@singleton
def Octet():
    """A 8-bit integer, must be enclosed in a Bitwise (eg. BitStruct)"""
    return BitsInteger(8)


@singleton
def Int8ub():
    """Unsigned, big endian 8-bit integer"""
    return FormatField(">", "B")


@singleton
def Int16ub():
    """Unsigned, big endian 16-bit integer"""
    return FormatField(">", "H")


@singleton
def Int32ub():
    """Unsigned, big endian 32-bit integer"""
    return FormatField(">", "L")


@singleton
def Int64ub():
    """Unsigned, big endian 64-bit integer"""
    return FormatField(">", "Q")


@singleton
def Int8sb():
    """Signed, big endian 8-bit integer"""
    return FormatField(">", "b")


@singleton
def Int16sb():
    """Signed, big endian 16-bit integer"""
    return FormatField(">", "h")


@singleton
def Int32sb():
    """Signed, big endian 32-bit integer"""
    return FormatField(">", "l")


@singleton
def Int64sb():
    """Signed, big endian 64-bit integer"""
    return FormatField(">", "q")


@singleton
def Int8ul():
    """Unsigned, little endian 8-bit integer"""
    return FormatField("<", "B")


@singleton
def Int16ul():
    """Unsigned, little endian 16-bit integer"""
    return FormatField("<", "H")


@singleton
def Int32ul():
    """Unsigned, little endian 32-bit integer"""
    return FormatField("<", "L")


@singleton
def Int64ul():
    """Unsigned, little endian 64-bit integer"""
    return FormatField("<", "Q")


@singleton
def Int8sl():
    """Signed, little endian 8-bit integer"""
    return FormatField("<", "b")


@singleton
def Int16sl():
    """Signed, little endian 16-bit integer"""
    return FormatField("<", "h")


@singleton
def Int32sl():
    """Signed, little endian 32-bit integer"""
    return FormatField("<", "l")


@singleton
def Int64sl():
    """Signed, little endian 64-bit integer"""
    return FormatField("<", "q")


@singleton
def Int8un():
    """Unsigned, native endianity 8-bit integer"""
    return FormatField("=", "B")


@singleton
def Int16un():
    """Unsigned, native endianity 16-bit integer"""
    return FormatField("=", "H")


@singleton
def Int32un():
    """Unsigned, native endianity 32-bit integer"""
    return FormatField("=", "L")


@singleton
def Int64un():
    """Unsigned, native endianity 64-bit integer"""
    return FormatField("=", "Q")


@singleton
def Int8sn():
    """Signed, native endianity 8-bit integer"""
    return FormatField("=", "b")


@singleton
def Int16sn():
    """Signed, native endianity 16-bit integer"""
    return FormatField("=", "h")


@singleton
def Int32sn():
    """Signed, native endianity 32-bit integer"""
    return FormatField("=", "l")


@singleton
def Int64sn():
    """Signed, native endianity 64-bit integer"""
    return FormatField("=", "q")


Byte = Int8ub
Short = Int16ub
Int = Int32ub
Long = Int64ub


@singleton
def Float16b():
    """Big endian, 16-bit IEEE 754 floating point number"""
    return FormatField(">", "e")


@singleton
def Float16l():
    """Little endian, 16-bit IEEE 754 floating point number"""
    return FormatField("<", "e")


@singleton
def Float16n():
    """Native endianity, 16-bit IEEE 754 floating point number"""
    return FormatField("=", "e")


@singleton
def Float32b():
    """Big endian, 32-bit IEEE floating point number"""
    return FormatField(">", "f")


@singleton
def Float32l():
    """Little endian, 32-bit IEEE floating point number"""
    return FormatField("<", "f")


@singleton
def Float32n():
    """Native endianity, 32-bit IEEE floating point number"""
    return FormatField("=", "f")


@singleton
def Float64b():
    """Big endian, 64-bit IEEE floating point number"""
    return FormatField(">", "d")


@singleton
def Float64l():
    """Little endian, 64-bit IEEE floating point number"""
    return FormatField("<", "d")


@singleton
def Float64n():
    """Native endianity, 64-bit IEEE floating point number"""
    return FormatField("=", "d")


Half = Float16b
Single = Float32b
Double = Float64b

native = sys.byteorder == "little"


@singleton
def Int24ub():
    """A 3-byte big-endian unsigned integer, as used in ancient file formats."""
    return BytesInteger(3, signed=False, swapped=False)


@singleton
def Int24ul():
    """A 3-byte little-endian unsigned integer, as used in ancient file formats."""
    return BytesInteger(3, signed=False, swapped=True)


@singleton
def Int24un():
    """A 3-byte native-endian unsigned integer, as used in ancient file formats."""
    return BytesInteger(3, signed=False, swapped=native)


@singleton
def Int24sb():
    """A 3-byte big-endian signed integer, as used in ancient file formats."""
    return BytesInteger(3, signed=True, swapped=False)


@singleton
def Int24sl():
    """A 3-byte little-endian signed integer, as used in ancient file formats."""
    return BytesInteger(3, signed=True, swapped=True)


@singleton
def Int24sn():
    """A 3-byte native-endian signed integer, as used in ancient file formats."""
    return BytesInteger(3, signed=True, swapped=native)


@singleton
class VarInt(Construct):
    r"""
    VarInt encoded unsigned integer. Each 7 bits of the number are encoded in one byte of the stream, where leftmost bit (MSB) is unset when byte is terminal. Scheme is defined at Google site related to `Protocol Buffers <https://developers.google.com/protocol-buffers/docs/encoding>`_.

    Can only encode non-negative numbers.

    Parses into an integer. Builds from an integer. Size is undefined.

    :raises StreamError: requested reading negative amount, could not read enough bytes, requested writing different amount than actual data, or could not write all bytes
    :raises IntegerError: given a negative value, or not an integer

    Example::

        >>> VarInt.build(1)
        b'\x01'
        >>> VarInt.build(2**100)
        b'\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x04'
    """

    def _parse(self, stream, context, path):
        acc = []
        while True:
            b = int.from_bytes((stream_read(stream, 1, path)), "little")
            acc.append(b & 0b01111111)
            if b & 0b10000000 == 0:
                break
        num = 0
        for b in reversed(acc):
            num = (num << 7) | b
        return num

    def _build(self, obj, stream, context, path):
        if not isinstance(obj, int):
            raise IntegerError(f"value {obj} is not an integer", path=path)
        if obj < 0:
            raise IntegerError(
                f"VarInt cannot build from negative number {obj}", path=path
            )
        x = obj
        B = bytearray()
        while x > 0b01111111:
            B.append(0b10000000 | (x & 0b01111111))
            x >>= 7
        B.append(x)
        stream_write(stream, bytes(B), len(B), path)
        return obj


@singleton
class ZigZag(Construct):
    r"""
    ZigZag encoded signed integer. This is a variant of VarInt encoding that also can encode negative numbers. Scheme is defined at Google site related to `Protocol Buffers <https://developers.google.com/protocol-buffers/docs/encoding>`_.

    Can also encode negative numbers.

    Parses into an integer. Builds from an integer. Size is undefined.

    :raises StreamError: requested reading negative amount, could not read enough bytes, requested writing different amount than actual data, or could not write all bytes
    :raises IntegerError: given not an integer

    Example::

        >>> ZigZag.build(-3)
        b'\x05'
        >>> ZigZag.build(3)
        b'\x06'
    """

    def _parse(self, stream, context, path):
        x = VarInt._parse(stream, context, path)
        if x & 1 == 0:
            x = x // 2
        else:
            x = -(x // 2 + 1)
        return x

    def _build(self, obj, stream, context, path):
        if not isinstance(obj, int):
            raise IntegerError(f"value {obj} is not an integer", path=path)
        if obj >= 0:
            x = 2 * obj
        else:
            x = 2 * abs(obj) - 1
        VarInt._build(x, stream, context, path)
        return obj
