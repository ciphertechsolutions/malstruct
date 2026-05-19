"""
Subconstruct transforms
"""

import binascii
import io
import itertools
import os
import zlib

from malstruct.lib import (
    Container,
    RebufferedBytesIO,
    RestreamedBytesIO,
    bits2bytes,
    bytes2bits,
    swapbitsinbytes,
    swapbytes,
)

from .bytes_ import Bytes, GreedyBytes
from .core import (
    Adapter,
    Construct,
    Renamed,
    Struct,
    Subconstruct,
    Tunnel,
    evaluate,
    this,
)
from .exceptions import *
from .expr import len_
from .helpers import (
    BytesIOWithOffsets,
    stream_read,
    stream_read_entire,
    stream_seek,
    stream_tell,
    stream_write,
)


def Bitwise(subcon):
    r"""
    Converts the stream from bytes to bits, and passes the bitstream to underlying subcon. Bitstream is a stream that contains 8 times as many bytes, and each byte is either \\x00 or \\x01 (in documentation those bytes are called bits).

    Parsing building and size are deferred to subcon, although size gets divided by 8 (therefore the subcon's size must be a multiple of 8).

    Note that by default the bit ordering is from MSB to LSB for every byte (ie. bit-level big-endian). If you need it reversed, wrap this subcon with :class:`malstruct.core.BitsSwapped`.

    :param subcon: Construct instance, any field that works with bits (like BitsInteger) or is bit-byte agnostic (like Struct or Flag)

    See :class:`~malstruct.core.Transformed` and :class:`~malstruct.core.Restreamed` for raisable exceptions.

    Example::

        >>> d = Bitwise(Struct(
        ...     'a' / Nibble,
        ...     'b' / Bytewise(Float32b),
        ...     'c' / Padding(4),
        ... ))
        >>> d.parse(bytes(5))
        Container(a=0, b=0.0, c=None)
        >>> d.sizeof()
        5

    Obtaining other byte or bit orderings::

        >>> d = Bitwise(Bytes(16))
        >>> d.parse(b'\x01\x03')
        b'\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x01\x01'
        >>> d = BitsSwapped(Bitwise(Bytes(16)))
        >>> d.parse(b'\x01\x03')
        b'\x01\x00\x00\x00\x00\x00\x00\x00\x01\x01\x00\x00\x00\x00\x00\x00'
    """

    try:
        size = subcon.sizeof()
        macro = Transformed(subcon, bytes2bits, size // 8, bits2bytes, size // 8)
    except SizeofError:
        macro = Restreamed(subcon, bytes2bits, 1, bits2bytes, 8, lambda n: n // 8)

    return macro


def Bytewise(subcon):
    r"""
    Converts the bitstream back to normal byte stream. Must be used within :class:`~malstruct.core.Bitwise`.

    Parsing building and size are deferred to subcon, although size gets multiplied by 8.

    :param subcon: Construct instance, any field that works with bytes or is bit-byte agnostic

    See :class:`~malstruct.core.Transformed` and :class:`~malstruct.core.Restreamed` for raisable exceptions.

    Example::

        >>> d = Bitwise(Struct(
        ...     'a' / Nibble,
        ...     'b' / Bytewise(Float32b),
        ...     'c' / Padding(4),
        ... ))
        >>> d.parse(bytes(5))
        Container(a=0, b=0.0, c=None)
        >>> d.sizeof()
        5
    """

    try:
        size = subcon.sizeof()
        macro = Transformed(subcon, bits2bytes, size * 8, bytes2bits, size * 8)
    except SizeofError:
        macro = Restreamed(subcon, bits2bytes, 8, bytes2bits, 1, lambda n: n * 8)

    return macro


def BitStruct(*subcons, **subconskw):
    r"""
    Makes a structure inside a Bitwise.

    See :class:`~malstruct.core.Bitwise` and :class:`~malstruct.core.Struct` for semantics and raisable exceptions.

    :param \*subcons: Construct instances, list of members, some can be anonymous
    :param \*\*subconskw: Construct instances, list of members (requires Python 3.6)

    Example::

        BitStruct  <-->  Bitwise(Struct(...))

        >>> d = BitStruct(
        ...     "a" / Flag,
        ...     "b" / Nibble,
        ...     "c" / BitsInteger(10),
        ...     "d" / Padding(1),
        ... )
        >>> d.parse(b"\xbe\xef")
        Container(a=True, b=7, c=887, d=None)
        >>> d.sizeof()
        2
    """
    return Bitwise(Struct(*subcons, **subconskw))


class RawCopy(Subconstruct):
    r"""
    Used to obtain byte representation of a field (aside of object value).

    Returns a dict containing both parsed subcon value, the raw bytes that were consumed by subcon, starting and ending offset in the stream, and amount in bytes. Builds either from raw bytes representation or a value used by subcon. Size is same as subcon.

    Object is a dictionary with either "data" or "value" keys, or both.

    When building, if both the "value" and "data" keys are present, then the "data" key is used and the "value" key is ignored. This is undesirable in the case that you parse some data for the purpose of modifying it and writing it back; in this case, delete the "data" key when modifying the "value" key to correctly rebuild the former.

    :param subcon: Construct instance

    :raises StreamError: stream is not seekable and tellable
    :raises RawCopyError: building and neither data or value was given
    :raises StringError: building from non-bytes value, perhaps unicode

    Example::

        >>> d = RawCopy(Byte)
        >>> d.parse(b"\xff")
        Container(data=b'\xff', value=255, offset1=0, offset2=1, length=1)
        >>> d.build(dict(data=b"\xff"))
        '\xff'
        >>> d.build(dict(value=255))
        '\xff'
    """

    def _parse(self, stream, context, path):
        offset1 = stream_tell(stream, path)
        obj = self.subcon._parsereport(stream, context, path)
        offset2 = stream_tell(stream, path)
        stream_seek(stream, offset1, 0, path)
        data = stream_read(stream, offset2 - offset1, path)
        return Container(
            data=data,
            value=obj,
            offset1=offset1,
            offset2=offset2,
            length=(offset2 - offset1),
        )

    def _build(self, obj, stream, context, path):
        if obj is None and self.subcon.flagbuildnone:
            obj = dict(value=None)
        if "data" in obj:
            data = obj["data"]
            offset1 = stream_tell(stream, path)
            stream_write(stream, data, len(data), path)
            offset2 = stream_tell(stream, path)
            return Container(
                obj,
                data=data,
                offset1=offset1,
                offset2=offset2,
                length=(offset2 - offset1),
            )
        if "value" in obj:
            value = obj["value"]
            offset1 = stream_tell(stream, path)
            buildret = self.subcon._build(value, stream, context, path)
            value = value if buildret is None else buildret
            offset2 = stream_tell(stream, path)
            stream_seek(stream, offset1, 0, path)
            data = stream_read(stream, offset2 - offset1, path)
            return Container(
                obj,
                data=data,
                value=value,
                offset1=offset1,
                offset2=offset2,
                length=(offset2 - offset1),
            )
        raise RawCopyError(
            "RawCopy cannot build, both data and value keys are missing", path=path
        )


def ByteSwapped(subcon):
    r"""
    Swaps the byte order within boundaries of given subcon. Requires a fixed sized subcon.

    :param subcon: Construct instance, subcon on top of byte swapped bytes

    :raises SizeofError: ctor or compiler could not compute subcon size

    See :class:`~malstruct.core.Transformed` and :class:`~malstruct.core.Restreamed` for raisable exceptions.

    Example::

        Int24ul <--> ByteSwapped(Int24ub) <--> BytesInteger(3, swapped=True) <--> ByteSwapped(BytesInteger(3))
    """

    size = subcon.sizeof()
    return Transformed(subcon, swapbytes, size, swapbytes, size)


def BitsSwapped(subcon):
    r"""
    Swaps the bit order within each byte within boundaries of given subcon. Does NOT require a fixed sized subcon.

    :param subcon: Construct instance, subcon on top of bit swapped bytes

    :raises SizeofError: compiler could not compute subcon size

    See :class:`~malstruct.core.Transformed` and :class:`~malstruct.core.Restreamed` for raisable exceptions.

    Example::

        >>> d = Bitwise(Bytes(8))
        >>> d.parse(b"\x01")
        '\x00\x00\x00\x00\x00\x00\x00\x01'
        >>>> BitsSwapped(d).parse(b"\x01")
        '\x01\x00\x00\x00\x00\x00\x00\x00'
    """

    try:
        size = subcon.sizeof()
        return Transformed(subcon, swapbitsinbytes, size, swapbitsinbytes, size)
    except SizeofError:
        return Restreamed(subcon, swapbitsinbytes, 1, swapbitsinbytes, 1, lambda n: n)


class FocusedSeq(Construct):
    r"""
    Allows constructing more elaborate "adapters" than Adapter class.

    Parse does parse all subcons in sequence, but returns only the element that was selected (discards other values). Build does build all subcons in sequence, where each gets build from nothing (except the selected subcon which is given the object). Size is the sum of all subcon sizes, unless any subcon raises SizeofError.

    This class does context nesting, meaning its members are given access to a new dictionary where the "_" entry points to the outer context. When parsing, each member gets parsed and subcon parse return value is inserted into context under matching key only if the member was named. When building, the matching entry gets inserted into context before subcon gets build, and if subcon build returns a new value (not None) that gets replaced in the context.

    This class exposes subcons as attributes. You can refer to subcons that were inlined (and therefore do not exist as variable in the namespace) by accessing the struct attributes, under same name. Also note that compiler does not support this feature. See examples.

    This class exposes subcons in the context. You can refer to subcons that were inlined (and therefore do not exist as variable in the namespace) within other inlined fields using the context. Note that you need to use a lambda (`this` expression is not supported). Also note that compiler does not support this feature. See examples.

    This class is used internally to implement :class:`~malstruct.core.PrefixedArray`.

    :param parsebuildfrom: string name or context lambda, selects a subcon
    :param \*subcons: Construct instances, list of members, some can be named
    :param \*\*subconskw: Construct instances, list of members (requires Python 3.6)

    :raises StreamError: requested reading negative amount, could not read enough bytes, requested writing different amount than actual data, or could not write all bytes
    :raises UnboundLocalError: selector does not match any subcon

    Can propagate any exception from the lambda, possibly non-ConstructError.

    Excample::

        >>> d = FocusedSeq("num", Const(b"SIG"), "num"/Byte, Terminated)
        >>> d.parse(b"SIG\xff")
        255
        >>> d.build(255)
        b'SIG\xff'

        >>> d = FocusedSeq("animal",
        ...     "animal" / Enum(Byte, giraffe=1),
        ... )
        >>> d.animal.giraffe
        'giraffe'
        >>> d = FocusedSeq("count",
        ...     "count" / Byte,
        ...     "data" / Padding(lambda this: this.count - this._subcons.count.sizeof()),
        ... )
        >>> d.build(4)
        b'\x04\x00\x00\x00'

        PrefixedArray <--> FocusedSeq("items",
            "count" / Rebuild(lengthfield, len_(this.items)),
            "items" / subcon[this.count],
        )
    """

    def __init__(self, parsebuildfrom, *subcons, **subconskw):
        super().__init__()
        self.parsebuildfrom = parsebuildfrom
        self.subcons = list(subcons) + list(k / v for k, v in subconskw.items())
        self._subcons = Container((sc.name, sc) for sc in self.subcons if sc.name)

    def __getattr__(self, name):
        if name in self._subcons:
            return self._subcons[name]
        raise AttributeError

    def _parse(self, stream, context, path):
        context = Container(
            _=context,
            _params=context._params,
            _root=None,
            _parsing=context._parsing,
            _building=context._building,
            _sizing=context._sizing,
            _subcons=self._subcons,
            _io=stream,
            _index=context.get("_index", None),
        )
        context._root = context._.get("_root", context)
        parsebuildfrom = evaluate(self.parsebuildfrom, context)

        found = False  # Must use separate flag because returning a parse result of None is valid.
        finalret = None
        for i, sc in enumerate(self.subcons):
            parseret = sc._parsereport(stream, context, path)
            context[i] = parseret
            if sc.name:
                context[sc.name] = parseret
            if sc.name == parsebuildfrom or i == parsebuildfrom:
                finalret = parseret
                found = True

        if not found:
            raise ConstructError("Unable to find entry: {}".format(parsebuildfrom))

        return finalret

    def _build(self, obj, stream, context, path):
        context = Container(
            _=context,
            _params=context._params,
            _root=None,
            _parsing=context._parsing,
            _building=context._building,
            _sizing=context._sizing,
            _subcons=self._subcons,
            _io=stream,
            _index=context.get("_index", None),
        )
        context._root = context._.get("_root", context)
        parsebuildfrom = evaluate(self.parsebuildfrom, context)

        context[parsebuildfrom] = obj
        found = False
        finalret = None
        for i, sc in enumerate(self.subcons):
            if sc.name == parsebuildfrom or i == parsebuildfrom:
                sub_obj = obj
            else:
                sub_obj = context._.get(sc.name, context._.get(i, None))
            buildret = sc._build(sub_obj, stream, context, path)

            context[i] = buildret
            if sc.name:
                context[sc.name] = buildret

            if sc.name == parsebuildfrom or i == parsebuildfrom:
                finalret = buildret
                found = True

        if not found:
            raise ConstructError("Unable to find entry: {}".format(parsebuildfrom))

        return finalret

    def _sizeof(self, context, path):
        # Removed the context manipulation.
        try:
            # Added back dereferencing nested context that was incorrectly removed.
            def isStruct(sc):
                return (
                    isStruct(sc.subcon)
                    if isinstance(sc, Renamed)
                    else isinstance(sc, Struct)
                )

            def nest(context, sc):
                # flagembedded was removed in 2.10
                if (
                    isStruct(sc)
                    and not getattr(sc, "flagembedded", False)
                    and sc.name in context
                ):
                    context2 = context[sc.name]
                    context2["_"] = context
                    return context2
                else:
                    return context

            return sum(sc._sizeof(nest(context, sc), path) for sc in self.subcons)
        except (KeyError, AttributeError):
            raise SizeofError("cannot calculate size, key not found in context")


def FocusLast(*subcons, **kw):
    r"""
    A helper for performing the common technique of using FocusedSeq to
    parse a bunch of subconstructs and then grab the last element.

    Example::

        >>> FocusLast(Byte, Byte, String(2)).parse(b'\x01\x02hi')
        'hi'

        >>> spec = FocusLast(
        ...     'a' / Byte,
        ...     'b' / Byte,
        ...     String(this.a + this.b),
        ... )
        >>> spec.parse(b'\x01\x02hi!')
        'hi!'
        >>> spec.build(u'hi!', a=1, b=2)
        b'\x01\x02hi!'

        # Simplifies this:
        >>> FocusedSeq(
            'value',
            're' / construct.Regex(.., offset=construct.Int32ul, size=construct.Byte),
            'value' / construct.PEPointer(this.re.offset, construct.Bytes(this.re.size)
        )
        # To this:
        >>> FocusLast(
            're' / construct.Regex(.., offset=construct.Int32ul, size=construct.Byte),
            construct.PEPointer(this.re.offset, construct.Bytes(this.re.size)
        )
    """
    return FocusedSeq(len(subcons) - 1, *subcons, **kw)


class Rebuild(Subconstruct):
    r"""
    Field where building does not require a value, because the value gets recomputed when needed. Comes handy when building a Struct from a dict with missing keys. Useful for length and count fields when :class:`~malstruct.core.Prefixed` and :class:`~malstruct.core.PrefixedArray` cannot be used.

    Parsing defers to subcon. Building is defered to subcon, but it builds from a value provided by the context lambda (or constant). Size is the same as subcon, unless it raises SizeofError.

    Difference between Default and Rebuild, is that in first the build value is optional and in second the build value is ignored.

    :param subcon: Construct instance
    :param func: context lambda or constant value

    :raises StreamError: requested reading negative amount, could not read enough bytes, requested writing different amount than actual data, or could not write all bytes

    Can propagate any exception from the lambda, possibly non-ConstructError.

    Example::

        >>> d = Struct(
        ...     "count" / Rebuild(Byte, len_(this.items)),
        ...     "items" / Byte[this.count],
        ... )
        >>> d.build(dict(items=[1,2,3]))
        b'\x03\x01\x02\x03'
    """

    def __init__(self, subcon, func):
        super().__init__(subcon)
        self.func = func
        self.flagbuildnone = True

    def _build(self, obj, stream, context, path):
        obj = evaluate(self.func, context)
        return self.subcon._build(obj, stream, context, path)


class Prefixed(Subconstruct):
    r"""
    Prefixes a field with byte count.

    Parses the length field. Then reads that amount of bytes, and parses subcon using only those bytes. Constructs that consume entire remaining stream are constrained to consuming only the specified amount of bytes (a substream). When building, data gets prefixed by its length. Optionally, length field can include its own size. Size is the sum of both fields sizes, unless either raises SizeofError.

    Analog to :class:`~malstruct.core.PrefixedArray` which prefixes with an element count, instead of byte count. Semantics is similar but implementation is different.

    :class:`~malstruct.core.VarInt` is recommended for new protocols, as it is more compact and never overflows.

    :param lengthfield: Construct instance, field used for storing the length
    :param subcon: Construct instance, subcon used for storing the value
    :param includelength: optional, bool, whether length field should include its own size, default is False
    :param absolute: Seek relative to the start of the stream rather than relative to the last occurence of a subconstruct

    :raises StreamError: requested reading negative amount, could not read enough bytes, requested writing different amount than actual data, or could not write all bytes

    Example::

        >>> d = Prefixed(VarInt, GreedyRange(Int32ul))
        >>> d.parse(b"\x08abcdefgh")
        [1684234849, 1751606885]

        >>> d = PrefixedArray(VarInt, Int32ul)
        >>> d.parse(b"\x02abcdefgh")
        [1684234849, 1751606885]
    """

    def __init__(self, lengthfield, subcon, includelength=False, absolute=False):
        super().__init__(subcon)
        self.lengthfield = lengthfield
        self.includelength = includelength
        self.absolute = absolute

    def _parse(self, stream, context, path):
        length = self.lengthfield._parsereport(stream, context, path)
        if self.includelength:
            length -= self.lengthfield._sizeof(context, path)
        substream = (
            BytesIOWithOffsets.from_reading(stream, length, path)
            if self.absolute
            else io.BytesIO(stream_read(stream, length, path))
        )
        return self.subcon._parsereport(substream, context, path)

    def _build(self, obj, stream, context, path):
        stream2 = io.BytesIO()
        buildret = self.subcon._build(obj, stream2, context, path)
        data = stream2.getvalue()
        length = len(data)
        if self.includelength:
            length += self.lengthfield._sizeof(context, path)
        self.lengthfield._build(length, stream, context, path)
        stream_write(stream, data, len(data), path)
        return buildret

    def _sizeof(self, context, path):
        return self.lengthfield._sizeof(context, path) + self.subcon._sizeof(
            context, path
        )

    def _actualsize(self, stream, context, path):
        position1 = stream_tell(stream, path)
        length = self.lengthfield._parse(stream, context, path)
        if self.includelength:
            length -= self.lengthfield._sizeof(context, path)
        position2 = stream_tell(stream, path)
        return (position2 - position1) + length


def PrefixedArray(countfield, subcon):
    r"""
    Prefixes an array with item count (as opposed to prefixed by byte count, see :class:`~malstruct.core.Prefixed`).

    :class:`~malstruct.core.VarInt` is recommended for new protocols, as it is more compact and never overflows.

    :param countfield: Construct instance, field used for storing the element count
    :param subcon: Construct instance, subcon used for storing each element

    :raises StreamError: requested reading negative amount, could not read enough bytes, requested writing different amount than actual data, or could not write all bytes
    :raises RangeError: consumed or produced too little elements

    Example::

        >>> d = Prefixed(VarInt, GreedyRange(Int32ul))
        >>> d.parse(b"\x08abcdefgh")
        [1684234849, 1751606885]

        >>> d = PrefixedArray(VarInt, Int32ul)
        >>> d.parse(b"\x02abcdefgh")
        [1684234849, 1751606885]
    """
    macro = FocusedSeq(
        "items",
        "count" / Rebuild(countfield, len_(this.items)),
        "items" / subcon[this.count],
    )

    def _actualsize(self, stream, context, path):
        position1 = stream_tell(stream, path)
        count = countfield._parse(stream, context, path)
        position2 = stream_tell(stream, path)
        return (position2 - position1) + count * subcon._sizeof(context, path)

    macro._actualsize = _actualsize

    return macro


class FixedSized(Subconstruct):
    r"""
    Restricts parsing to specified amount of bytes.

    Parsing reads `length` bytes, then defers to subcon using new BytesIO with said bytes. Building builds the subcon using new BytesIO, then writes said data and additional null bytes accordingly. Size is same as `length`, although negative amount raises an error.

    :param length: integer or context lambda, total amount of bytes (both data and padding)
    :param subcon: Construct instance
    :param absolute: Seek relative to the start of the stream rather than relative to the last occurence of a subconstruct

    :raises StreamError: requested reading negative amount, could not read enough bytes, requested writing different amount than actual data, or could not write all bytes
    :raises PaddingError: length is negative
    :raises PaddingError: subcon written more bytes than entire length (negative padding)

    Can propagate any exception from the lambda, possibly non-ConstructError.

    Example::

        >>> d = FixedSized(10, Byte)
        >>> d.parse(b'\xff\x00\x00\x00\x00\x00\x00\x00\x00\x00')
        255
        >>> d.build(255)
        b'\xff\x00\x00\x00\x00\x00\x00\x00\x00\x00'
        >>> d.sizeof()
        10
    """

    def __init__(self, length, subcon, absolute=False):
        super().__init__(subcon)
        self.length = length
        self.absolute = absolute

    def _parse(self, stream, context, path):
        length = evaluate(self.length, context)
        if length < 0:
            raise PaddingError("length cannot be negative", path=path)
        substream = (
            BytesIOWithOffsets.from_reading(stream, length, path)
            if self.absolute
            else io.BytesIO(stream_read(stream, length, path))
        )
        return self.subcon._parsereport(substream, context, path)

    def _build(self, obj, stream, context, path):
        length = evaluate(self.length, context)
        if length < 0:
            raise PaddingError("length cannot be negative", path=path)
        stream2 = io.BytesIO()
        buildret = self.subcon._build(obj, stream2, context, path)
        data = stream2.getvalue()
        pad = length - len(data)
        if pad < 0:
            raise PaddingError(
                "subcon build %d bytes but was allowed only %d" % (len(data), length),
                path=path,
            )
        stream_write(stream, data, len(data), path)
        stream_write(stream, bytes(pad), pad, path)
        return buildret

    def _sizeof(self, context, path):
        length = evaluate(self.length, context)
        if length < 0:
            raise PaddingError("length cannot be negative", path=path)
        return length


class NullTerminated(Subconstruct):
    r"""
    Restricts parsing to bytes preceding a null byte.

    Parsing reads one byte at a time and accumulates it with previous bytes. When term was found, (by default) consumes but discards the term. When EOF was found, (by default) raises same StreamError exception. Then subcon is parsed using new BytesIO made with said data. Building builds the subcon and then writes the term. Size is undefined.

    The term can be multiple bytes, to support string classes with UTF16/32 encodings for example. Be warned however: as reported in Issue 1046, the data read must be a multiple of the term length and the term must start at a unit boundary, otherwise strange things happen when parsing.

    :param subcon: Construct instance
    :param term: optional, bytes, terminator byte-string, default is \x00 single null byte
    :param include: optional, bool, if to include terminator in resulting data, default is False
    :param consume: optional, bool, if to consume terminator or leave it in the stream, default is True
    :param require: optional, bool, if EOF results in failure or not, default is True
    :param absolute: Seek relative to the start of the stream rather than relative to the last occurence of a subconstruct

    :raises StreamError: requested reading negative amount, could not read enough bytes, requested writing different amount than actual data, or could not write all bytes
    :raises StreamError: encountered EOF but require is not disabled
    :raises PaddingError: terminator is less than 1 bytes in length

    Example::

        >>> d = NullTerminated(Byte)
        >>> d.parse(b'\xff\x00')
        255
        >>> d.build(255)
        b'\xff\x00'
    """

    def __init__(
        self,
        subcon,
        term=b"\x00",
        include=False,
        consume=True,
        require=True,
        absolute=False,
    ):
        super().__init__(subcon)
        self.term = term
        self.include = include
        self.consume = consume
        self.require = require
        self.absolute = absolute

    def _parse(self, stream, context, path):
        term = self.term
        unit = len(term)
        if unit < 1:
            raise PaddingError("NullTerminated term must be at least 1 byte", path=path)
        data = b""
        offset = stream_tell(stream, path)
        while True:
            try:
                b = stream_read(stream, unit, path)
            except StreamError:
                if self.require:
                    raise
                else:
                    break
            if b == term:
                if self.include:
                    data += b
                if not self.consume:
                    stream_seek(stream, -unit, 1, path)
                break
            data += b

        substream = (
            BytesIOWithOffsets(data, stream, offset)
            if self.absolute
            else io.BytesIO(data)
        )
        return self.subcon._parsereport(substream, context, path)

    def _build(self, obj, stream, context, path):
        buildret = self.subcon._build(obj, stream, context, path)
        stream_write(stream, self.term, len(self.term), path)
        return buildret

    def _sizeof(self, context, path):
        raise SizeofError(path=path)


# Continuously parses until it hits the first zero byte (consumed).
# Use this instead of CString() if you can't guarantee it won't fail to decode.
CBytes = NullTerminated(GreedyBytes)


class NullStripped(Subconstruct):
    r"""
    Restricts parsing to bytes except padding left of EOF.

    Parsing reads entire stream, then strips the data from right to left of null bytes, then parses subcon using new BytesIO made of said data. Building defers to subcon as-is. Size is undefined, because it reads till EOF.

    The pad can be multiple bytes, to support string classes with UTF16/32 encodings.

    :param subcon: Construct instance
    :param pad: optional, bytes, padding byte-string, default is \x00 single null byte
    :param absolute: Seek relative to the start of the stream rather than relative to the last occurence of a subconstruct

    :raises PaddingError: pad is less than 1 bytes in length

    Example::

        >>> d = NullStripped(Byte)
        >>> d.parse(b'\xff\x00\x00')
        255
        >>> d.build(255)
        b'\xff'
    """

    def __init__(self, subcon, pad=b"\x00", absolute=False):
        super().__init__(subcon)
        self.pad = pad
        self.absolute = absolute

    def _parse(self, stream, context, path):
        pad = self.pad
        unit = len(pad)
        if unit < 1:
            raise PaddingError("NullStripped pad must be at least 1 byte", path=path)
        offset = stream_tell(stream, path)
        data = stream_read_entire(stream, path)
        if unit == 1:
            data = data.rstrip(pad)
        else:
            tailunit = len(data) % unit
            end = len(data)
            if tailunit and data[-tailunit:] == pad[:tailunit]:
                end -= tailunit
            while end - unit >= 0 and data[end - unit : end] == pad:
                end -= unit
            data = data[:end]

        substream = (
            BytesIOWithOffsets(data, stream, offset)
            if self.absolute
            else io.BytesIO(data)
        )
        return self.subcon._parsereport(substream, context, path)

    def _build(self, obj, stream, context, path):
        return self.subcon._build(obj, stream, context, path)

    def _sizeof(self, context, path):
        raise SizeofError(path=path)


class RestreamData(Subconstruct):
    r"""
    Parses a field on external data (but does not build).

    Parsing defers to subcon, but provides it a separate BytesIO stream based on data provided by datafunc (a bytes literal or another BytesIO stream or Construct instances that returns bytes or context lambda). Building does nothing. Size is 0 because as far as other fields see it, this field does not produce or consume any bytes from the stream.

    :param datafunc: bytes or BytesIO or Construct instance (that parses into bytes) or context lambda, provides data for subcon to parse from
    :param subcon: Construct instance

    Can propagate any exception from the lambdas, possibly non-ConstructError.

    Example::

        >>> d = RestreamData(b"\x01", Int8ub)
        >>> d.parse(b"")
        1
        >>> d.build(0)
        b''

        >>> d = RestreamData(NullTerminated(GreedyBytes), Int16ub)
        >>> d.parse(b"\x01\x02\x00")
        0x0102
        >>> d = RestreamData(FixedSized(2, GreedyBytes), Int16ub)
        >>> d.parse(b"\x01\x02\x00")
        0x0102
    """

    def __init__(self, datafunc, subcon):
        super().__init__(subcon)
        self.datafunc = datafunc
        self.flagbuildnone = True

    def _parse(self, stream, context, path):
        data = evaluate(self.datafunc, context)
        if isinstance(data, bytes):
            stream2 = io.BytesIO(data)
        if isinstance(data, io.BytesIO):
            stream2 = data
        if isinstance(data, Construct):
            stream2 = io.BytesIO(data._parsereport(stream, context, path))
        return self.subcon._parsereport(stream2, context, path)

    def _build(self, obj, stream, context, path):
        return obj

    def _sizeof(self, context, path):
        return 0


class Transformed(Subconstruct):
    r"""
    Transforms bytes between the underlying stream and the (fixed-sized) subcon.

    Parsing reads a specified amount (or till EOF), processes data using a bytes-to-bytes decoding function, then parses subcon using those data. Building does build subcon into separate bytes, then processes it using encoding bytes-to-bytes function, then writes those data into main stream. Size is reported as `decodeamount` or `encodeamount` if those are equal, otherwise its SizeofError.

    Used internally to implement :class:`~malstruct.core.Bitwise` :class:`~malstruct.core.Bytewise` :class:`~malstruct.core.ByteSwapped` :class:`~malstruct.core.BitsSwapped` .

    Possible use-cases include encryption, obfuscation, byte-level encoding.

    .. warning:: Remember that subcon must consume (or produce) an amount of bytes that is same as `decodeamount` (or `encodeamount`).

    .. warning:: Do NOT use seeking/telling classes inside Transformed context.

    :param subcon: Construct instance
    :param decodefunc: bytes-to-bytes function, applied before parsing subcon
    :param decodeamount: integer, amount of bytes to read
    :param encodefunc: bytes-to-bytes function, applied after building subcon
    :param encodeamount: integer, amount of bytes to write

    :raises StreamError: requested reading negative amount, could not read enough bytes, requested writing different amount than actual data, or could not write all bytes
    :raises StreamError: subcon build and encoder transformed more or less than `encodeamount` bytes, if amount is specified
    :raises StringError: building from non-bytes value, perhaps unicode

    Can propagate any exception from the lambdas, possibly non-ConstructError.

    Example::

        >>> d = Transformed(Bytes(16), bytes2bits, 2, bits2bytes, 2)
        >>> d.parse(b"\x00\x00")
        b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'

        >>> d = Transformed(GreedyBytes, bytes2bits, None, bits2bytes, None)
        >>> d.parse(b"\x00\x00")
        b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
    """

    def __init__(self, subcon, decodefunc, decodeamount, encodefunc, encodeamount):
        super().__init__(subcon)
        self.decodefunc = decodefunc
        self.decodeamount = decodeamount
        self.encodefunc = encodefunc
        self.encodeamount = encodeamount

    def _parse(self, stream, context, path):
        if isinstance(self.decodeamount, type(None)):
            data = stream_read_entire(stream, path)
        if isinstance(self.decodeamount, int):
            data = stream_read(stream, self.decodeamount, path)
        data = self.decodefunc(data)
        return self.subcon._parsereport(io.BytesIO(data), context, path)

    def _build(self, obj, stream, context, path):
        stream2 = io.BytesIO()
        buildret = self.subcon._build(obj, stream2, context, path)
        data = stream2.getvalue()
        data = self.encodefunc(data)
        if isinstance(self.encodeamount, int):
            if len(data) != self.encodeamount:
                raise StreamError(
                    "encoding transformation produced wrong amount of bytes, {} instead of expected {}".format(
                        len(data), self.encodeamount
                    ),
                    path=path,
                )
        stream_write(stream, data, len(data), path)
        return buildret

    def _sizeof(self, context, path):
        if self.decodeamount is None or self.encodeamount is None:
            raise SizeofError(path=path)
        if self.decodeamount == self.encodeamount:
            return self.encodeamount
        raise SizeofError(path=path)


class Restreamed(Subconstruct):
    r"""
    Transforms bytes between the underlying stream and the (variable-sized) subcon.

    Used internally to implement :class:`~malstruct.core.Bitwise` :class:`~malstruct.core.Bytewise` :class:`~malstruct.core.ByteSwapped` :class:`~malstruct.core.BitsSwapped` .

    .. warning:: Remember that subcon must consume or produce an amount of bytes that is a multiple of encoding or decoding units. For example, in a Bitwise context you should process a multiple of 8 bits or the stream will fail during parsing/building.

    .. warning:: Do NOT use seeking/telling classes inside Restreamed context.

    :param subcon: Construct instance
    :param decoder: bytes-to-bytes function, used on data chunks when parsing
    :param decoderunit: integer, decoder takes chunks of this size
    :param encoder: bytes-to-bytes function, used on data chunks when building
    :param encoderunit: integer, encoder takes chunks of this size
    :param sizecomputer: function that computes amount of bytes outputed

    Can propagate any exception from the lambda, possibly non-ConstructError.
    Can also raise arbitrary exceptions in RestreamedBytesIO implementation.

    Example::

        Bitwise  <--> Restreamed(subcon, bits2bytes, 8, bytes2bits, 1, lambda n: n//8)
        Bytewise <--> Restreamed(subcon, bytes2bits, 1, bits2bytes, 8, lambda n: n*8)
    """

    def __init__(
        self, subcon, decoder, decoderunit, encoder, encoderunit, sizecomputer
    ):
        super().__init__(subcon)
        self.decoder = decoder
        self.decoderunit = decoderunit
        self.encoder = encoder
        self.encoderunit = encoderunit
        self.sizecomputer = sizecomputer

    def _parse(self, stream, context, path):
        stream2 = RestreamedBytesIO(
            stream, self.decoder, self.decoderunit, self.encoder, self.encoderunit
        )
        obj = self.subcon._parsereport(stream2, context, path)
        stream2.close()
        return obj

    def _build(self, obj, stream, context, path):
        stream2 = RestreamedBytesIO(
            stream, self.decoder, self.decoderunit, self.encoder, self.encoderunit
        )
        buildret = self.subcon._build(obj, stream2, context, path)
        stream2.close()
        return obj

    def _sizeof(self, context, path):
        if self.sizecomputer is None:
            raise SizeofError(
                "Restreamed cannot calculate size without a sizecomputer", path=path
            )
        else:
            return self.sizecomputer(self.subcon._sizeof(context, path))


class ProcessXor(Subconstruct):
    r"""
    Transforms bytes between the underlying stream and the subcon.

    Used internally by KaitaiStruct compiler, when translating `process: xor` tags.

    Parsing reads till EOF, xors data with the pad, then feeds that data into subcon. Building first builds the subcon into separate BytesIO stream, xors data with the pad, then writes that data into the main stream. Size is the same as subcon, unless it raises SizeofError.

    :param padfunc: integer or bytes or context lambda, single or multiple bytes to xor data with
    :param subcon: Construct instance
    :param absolute: Seek relative to the start of the stream rather than relative to the last occurence of a subconstruct

    :raises StringError: pad is not integer or bytes

    Can propagate any exception from the lambda, possibly non-ConstructError.

    Example::

        >>> d = ProcessXor(0xf0 or b'\xf0', Int16ub)
        >>> d.parse(b"\x00\xff")
        0xf00f
        >>> d.sizeof()
        2
    """

    def __init__(self, padfunc, subcon, absolute=False):
        super().__init__(subcon)
        self.padfunc = padfunc
        self.absolute = absolute

    def _parse(self, stream, context, path):
        pad = evaluate(self.padfunc, context)
        if not isinstance(pad, (int, bytes)):
            raise StringError("ProcessXor needs integer or bytes pad", path=path)
        if isinstance(pad, bytes) and len(pad) == 1:
            pad = int.from_bytes(pad, "little")
        offset = stream_tell(stream, path)
        data = stream_read_entire(stream, path)
        if isinstance(pad, int):
            if not (pad == 0):
                data = bytes((b ^ pad) for b in data)
        if isinstance(pad, bytes):
            if not (len(pad) <= 64 and pad == bytes(len(pad))):
                data = bytes((b ^ p) for b, p in zip(data, itertools.cycle(pad)))

        substream = (
            BytesIOWithOffsets(data, stream, offset)
            if self.absolute
            else io.BytesIO(data)
        )
        return self.subcon._parsereport(substream, context, path)

    def _build(self, obj, stream, context, path):
        pad = evaluate(self.padfunc, context)
        if not isinstance(pad, (int, bytes)):
            raise StringError("ProcessXor needs integer or bytes pad", path=path)
        if isinstance(pad, bytes) and len(pad) == 1:
            pad = int.from_bytes(pad, "little")
        stream2 = io.BytesIO()
        buildret = self.subcon._build(obj, stream2, context, path)
        data = stream2.getvalue()
        if isinstance(pad, int):
            if not (pad == 0):
                data = bytes((b ^ pad) for b in data)
        if isinstance(pad, bytes):
            if not (len(pad) <= 64 and pad == bytes(len(pad))):
                data = bytes((b ^ p) for b, p in zip(data, itertools.cycle(pad)))
        stream_write(stream, data, len(data), path)
        return buildret

    def _sizeof(self, context, path):
        return self.subcon._sizeof(context, path)


class ProcessRotateLeft(Subconstruct):
    r"""
    Transforms bytes between the underlying stream and the subcon.

    Used internally by KaitaiStruct compiler, when translating `process: rol/ror` tags.

    Parsing reads till EOF, rotates (shifts) the data *left* by amount in bits, then feeds that data into subcon. Building first builds the subcon into separate BytesIO stream, rotates *right* by negating amount, then writes that data into the main stream. Size is the same as subcon, unless it raises SizeofError.

    :param amount: integer or context lambda, shift by this amount in bits, treated modulo (group x 8)
    :param group: integer or context lambda, shifting is applied to chunks of this size in bytes
    :param subcon: Construct instance

    :raises RotationError: group is less than 1
    :raises RotationError: data length is not a multiple of group size

    Can propagate any exception from the lambda, possibly non-ConstructError.

    Example::

        >>> d = ProcessRotateLeft(4, 1, Int16ub)
        >>> d.parse(b'\x0f\xf0')
        0xf00f
        >>> d = ProcessRotateLeft(4, 2, Int16ub)
        >>> d.parse(b'\x0f\xf0')
        0xff00
        >>> d.sizeof()
        2
    """

    # formula taken from: http://stackoverflow.com/a/812039
    precomputed_single_rotations = {
        amount: [(i << amount) & 0xFF | (i >> (8 - amount)) for i in range(256)]
        for amount in range(1, 8)
    }

    def __init__(self, amount, group, subcon):
        super().__init__(subcon)
        self.amount = amount
        self.group = group

    def _parse(self, stream, context, path):
        amount = evaluate(self.amount, context)
        group = evaluate(self.group, context)
        if group < 1:
            raise RotationError("group size must be at least 1 to be valid", path=path)

        amount = amount % (group * 8)
        amount_bytes = amount // 8
        data = stream_read_entire(stream, path)

        if len(data) % group != 0:
            raise RotationError(
                "data length must be a multiple of group size", path=path
            )

        if amount == 0:
            pass

        elif group == 1:
            translate = ProcessRotateLeft.precomputed_single_rotations[amount]
            data = bytes(translate[a] for a in data)

        elif amount % 8 == 0:
            indices = [(i + amount_bytes) % group for i in range(group)]
            data = bytes(
                data[i + k] for i in range(0, len(data), group) for k in indices
            )

        else:
            amount1 = amount % 8
            amount2 = 8 - amount1
            indices_pairs = [
                ((i + amount_bytes) % group, (i + 1 + amount_bytes) % group)
                for i in range(group)
            ]
            data = bytes(
                (data[i + k1] << amount1) & 0xFF | (data[i + k2] >> amount2)
                for i in range(0, len(data), group)
                for k1, k2 in indices_pairs
            )

        return self.subcon._parsereport(io.BytesIO(data), context, path)

    def _build(self, obj, stream, context, path):
        amount = evaluate(self.amount, context)
        group = evaluate(self.group, context)
        if group < 1:
            raise RotationError("group size must be at least 1 to be valid", path=path)

        amount = -amount % (group * 8)
        amount_bytes = amount // 8
        stream2 = io.BytesIO()
        buildret = self.subcon._build(obj, stream2, context, path)
        data = stream2.getvalue()

        if len(data) % group != 0:
            raise RotationError(
                "data length must be a multiple of group size", path=path
            )

        if amount == 0:
            pass

        elif group == 1:
            translate = ProcessRotateLeft.precomputed_single_rotations[amount]
            data = bytes(translate[a] for a in data)

        elif amount % 8 == 0:
            indices = [(i + amount_bytes) % group for i in range(group)]
            data = bytes(
                data[i + k] for i in range(0, len(data), group) for k in indices
            )

        else:
            amount1 = amount % 8
            amount2 = 8 - amount1
            indices_pairs = [
                ((i + amount_bytes) % group, (i + 1 + amount_bytes) % group)
                for i in range(group)
            ]
            data = bytes(
                (data[i + k1] << amount1) & 0xFF | (data[i + k2] >> amount2)
                for i in range(0, len(data), group)
                for k1, k2 in indices_pairs
            )

        stream_write(stream, data, len(data), path)
        return buildret

    def _sizeof(self, context, path):
        return self.subcon._sizeof(context, path)


class Checksum(Construct):
    r"""
    Field that is build or validated by a hash of a given byte range. Usually used with :class:`~malstruct.core.RawCopy` .

    Parsing compares parsed subcon `checksumfield` with a context entry provided by `bytesfunc` and transformed by `hashfunc`. Building fetches the contect entry, transforms it, then writes is using subcon. Size is same as subcon.

    :param checksumfield: a subcon field that reads the checksum, usually Bytes(int)
    :param hashfunc: function that takes bytes and returns whatever checksumfield takes when building, usually from hashlib module
    :param bytesfunc: context lambda that returns bytes (or object) to be hashed, usually like this.rawcopy1.data

    :raises ChecksumError: parsing and actual checksum does not match actual data

    Can propagate any exception from the lambdas, possibly non-ConstructError.

    Example::

        import hashlib
        d = Struct(
            "fields" / RawCopy(Struct(
                Padding(1000),
            )),
            "checksum" / Checksum(Bytes(64),
                lambda data: hashlib.sha512(data).digest(),
                this.fields.data),
        )
        d.build(dict(fields=dict(value={})))

    ::

        import hashlib
        d = Struct(
            "offset" / Tell,
            "checksum" / Padding(64),
            "fields" / RawCopy(Struct(
                Padding(1000),
            )),
            "checksum" / Pointer(this.offset, Checksum(Bytes(64),
                lambda data: hashlib.sha512(data).digest(),
                this.fields.data)),
        )
        d.build(dict(fields=dict(value={})))
    """

    def __init__(self, checksumfield, hashfunc, bytesfunc):
        super().__init__()
        self.checksumfield = checksumfield
        self.hashfunc = hashfunc
        self.bytesfunc = bytesfunc
        self.flagbuildnone = True

    def _parse(self, stream, context, path):
        hash1 = self.checksumfield._parsereport(stream, context, path)
        hash2 = self.hashfunc(self.bytesfunc(context))
        if hash1 != hash2:
            raise ChecksumError(
                "wrong checksum, read {!r}, computed {!r}".format(
                    hash1 if not isinstance(hash1, bytes) else binascii.hexlify(hash1),
                    hash2 if not isinstance(hash2, bytes) else binascii.hexlify(hash2),
                ),
                path=path,
            )
        return hash1

    def _build(self, obj, stream, context, path):
        hash2 = self.hashfunc(self.bytesfunc(context))
        self.checksumfield._build(hash2, stream, context, path)
        return hash2

    def _sizeof(self, context, path):
        return self.checksumfield._sizeof(context, path)


class Compressed(Adapter):
    r"""
    Compresses and decompresses underlying stream when processing subcon. When parsing, entire stream is consumed. When building, it puts compressed bytes without marking the end. This construct should be used with :class:`~malstruct.core.Prefixed` .

    Parsing and building transforms all bytes using a specified codec. Since data is processed until EOF, it behaves similar to `GreedyBytes`. Size is undefined.
        - supports providing a custom encoding module or object.
        - (provide any object that has a "decompress" and "compress" function in the lib parameter.)
        - produces a ConstructError if compressed/decompression fails.
            - (You can turn this off by setting wrap_exception=False)
        - uses Adapter instead of Tunnel in order to allow it be embedded within other constructs.
            - (Original one read entire stream, no matter the subcon you provide.)


    :param subcon: Construct instance, subcon used for storing the value
    :param encoding: string, any of module names like zlib/gzip/bzip2/lzma, otherwise any of codecs module bytes<->bytes encodings, each codec usually requires some Python version
    :param level: optional, integer between 0..9, although lzma discards it, some encoders allow different compression levels

    :raises ImportError: needed module could not be imported by ctor
    :raises StreamError: stream failed when reading until EOF

    Example::

        >>> d = Prefixed(VarInt, Compressed(GreedyBytes, "zlib"))
        >>> d.build(bytes(100))
        b'\x0cx\x9cc`\xa0=\x00\x00\x00d\x00\x01'
        >>> len(_)
        13
    """

    __slots__ = ["lib", "wrap_exception"]

    def __init__(
        self, subcon, lib, wrap_exception=True, encode_args={}, decode_args={}
    ):
        super().__init__(subcon)
        self.wrap_exception = wrap_exception
        self.encode_args = encode_args
        self.decode_args = decode_args
        if hasattr(lib, "compress") and hasattr(lib, "decompress"):
            self.lib = lib
        elif lib == "zlib":
            import zlib

            self.lib = zlib
        elif lib == "gzip":
            import gzip

            self.lib = gzip
        elif lib == "bzip2":
            import bz2

            self.lib = bz2
        elif lib == "lzma":
            import lzma

            self.lib = lzma
        else:
            raise ValueError(f"Invalid lib parameter: {lib}")

    def _decode(self, data, context, path):
        try:
            return self.lib.decompress(data, **self.decode_args)
        except Exception as e:
            if self.wrap_exception:
                raise ConstructError(f"Decompression failed with error: {e}")
            else:
                raise

    def _encode(self, data, context, path):
        try:
            return self.lib.compress(data, **self.encode_args)
        except Exception as e:
            if self.wrap_exception:
                raise ConstructError(f"Compression failed with error: {e}")
            else:
                raise


class ZLIB(Adapter):
    r"""
    Adapter used to zlib compress/decompress a data buffer

    :param subcon: The construct to wrap
    :param int level: The zlib compression level
    :param int wbits: The zlib decompression window size
    :param int bufsize: The initial output buffer size

    >>> ZLIB(Bytes(12)).build(b'data')
    b'x\x9cKI,I\x04\x00\x04\x00\x01\x9b'
    >>> ZLIB(GreedyBytes, level=0).build(b'data')
    b'x\x01\x01\x04\x00\xfb\xffdata\x04\x00\x01\x9b'
    >>> ZLIB(GreedyBytes).parse(b'x^KI,I\x04\x00\x04\x00\x01\x9b')
    b'data'
    """

    def __init__(self, subcon, wbits=None, bufsize=None, level=None):
        super().__init__(subcon)
        self.wbits = wbits
        self.bufsize = bufsize
        self.level = level

    def _encode(self, obj, context, path):
        level = self.level(context) if callable(self.level) else self.level
        if level is not None:
            return zlib.compress(obj, level)
        return zlib.compress(obj)

    def _decode(self, obj, context, path):
        """
        ZLIB decompress a buffer, cannot use bufsize if wbits is not set

        :param obj:
        :param context:

        :return:
        """
        wbits = self.wbits(context) if callable(self.wbits) else self.wbits
        bufsize = self.bufsize(context) if callable(self.bufsize) else self.bufsize
        if wbits is not None and bufsize is not None:
            return zlib.decompress(obj, wbits, bufsize)
        elif wbits is not None:
            return zlib.decompress(obj, wbits)
        return zlib.decompress(obj)


class CompressedLZ4(Tunnel):
    r"""
    Compresses and decompresses underlying stream before processing subcon. When parsing, entire stream is consumed. When building, it puts compressed bytes without marking the end. This construct should be used with :class:`~malstruct.core.Prefixed` .

    Parsing and building transforms all bytes using LZ4 library. Since data is processed until EOF, it behaves similar to `GreedyBytes`. Size is undefined.

    :param subcon: Construct instance, subcon used for storing the value

    :raises ImportError: needed module could not be imported by ctor
    :raises StreamError: stream failed when reading until EOF

    Can propagate lz4.frame exceptions.

    Example::

        >>> d = Prefixed(VarInt, CompressedLZ4(GreedyBytes))
        >>> d.build(bytes(100))
        b'"\x04"M\x18h@d\x00\x00\x00\x00\x00\x00\x00#\x0b\x00\x00\x00\x1f\x00\x01\x00KP\x00\x00\x00\x00\x00\x00\x00\x00\x00'
        >>> len(_)
        35
    """

    def __init__(self, subcon):
        super().__init__(subcon)
        import lz4.frame

        self.lib = lz4.frame

    def _decode(self, data, context, path):
        return self.lib.decompress(data)

    def _encode(self, data, context, path):
        return self.lib.compress(data)


class EncryptedSym(Tunnel):
    r"""
    Perform symmetrical encryption and decryption of the underlying stream before processing subcon. When parsing, entire stream is consumed. When building, it puts encrypted bytes without marking the end.

    Parsing and building transforms all bytes using the selected cipher. Since data is processed until EOF, it behaves similar to `GreedyBytes`. Size is undefined.

    The key for encryption and decryption should be passed via `contextkw` to `build` and `parse` methods.

    This construct is heavily based on the `cryptography` library, which supports the following algorithms and modes. For more details please see the documentation of that library.

    Algorithms:
    - AES
    - Camellia
    - ChaCha20
    - TripleDES
    - CAST5
    - SEED
    - SM4
    - Blowfish (weak cipher)
    - ARC4 (weak cipher)
    - IDEA (weak cipher)

    Modes:
    - CBC
    - CTR
    - OFB
    - CFB
    - CFB8
    - XTS
    - ECB (insecure)

    .. note:: Keep in mind that some of the algorithms require padding of the data. This can be done e.g. with :class:`~malstruct.core.Aligned`.
    .. note:: For GCM mode use :class:`~malstruct.core.EncryptedSymAead`.

    :param subcon: Construct instance, subcon used for storing the value
    :param cipher: Cipher object or context lambda from cryptography.hazmat.primitives.ciphers

    :raises ImportError: needed module could not be imported
    :raises StreamError: stream failed when reading until EOF
    :raises CipherError: no cipher object is provided
    :raises CipherError: an AEAD cipher is used

    Can propagate cryptography.exceptions exceptions.

    Example::

        >>> from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        >>> d = Struct(
        ...     "iv" / Default(Bytes(16), os.urandom(16)),
        ...     "enc_data" / EncryptedSym(
        ...         Aligned(16,
        ...             Struct(
        ...                 "width" / Int16ul,
        ...                 "height" / Int16ul,
        ...             )
        ...         ),
        ...         lambda ctx: Cipher(algorithms.AES(ctx._.key), modes.CBC(ctx.iv))
        ...     )
        ... )
        >>> key128 = b"\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f"
        >>> d.build({"enc_data": {"width": 5, "height": 4}}, key=key128)
        b"o\x11i\x98~H\xc9\x1c\x17\x83\xf6|U:\x1a\x86+\x00\x89\xf7\x8e\xc3L\x04\t\xca\x8a\xc8\xc2\xfb'\xc8"
        >>> d.parse(b"o\x11i\x98~H\xc9\x1c\x17\x83\xf6|U:\x1a\x86+\x00\x89\xf7\x8e\xc3L\x04\t\xca\x8a\xc8\xc2\xfb'\xc8", key=key128)
        Container:
            iv = b'o\x11i\x98~H\xc9\x1c\x17\x83\xf6|U:\x1a\x86' (total 16)
            enc_data = Container:
                width = 5
                height = 4
    """

    def __init__(self, subcon, cipher):
        import cryptography

        super().__init__(subcon)
        self.cipher = cipher

    def _evaluate_cipher(self, context, path):
        from cryptography.hazmat.primitives.ciphers import Cipher, modes

        cipher = evaluate(self.cipher, context)
        if not isinstance(cipher, Cipher):
            raise CipherError(
                f"cipher {repr(cipher)} is not a cryptography.hazmat.primitives.ciphers.Cipher object",
                path=path,
            )
        if isinstance(cipher.mode, modes.GCM):
            raise CipherError(
                f"AEAD cipher is not supported in this class, use EncryptedSymAead",
                path=path,
            )
        return cipher

    def _decode(self, data, context, path):
        cipher = self._evaluate_cipher(context, path)
        decryptor = cipher.decryptor()
        return decryptor.update(data) + decryptor.finalize()

    def _encode(self, data, context, path):
        cipher = self._evaluate_cipher(context, path)
        encryptor = cipher.encryptor()
        return encryptor.update(data) + encryptor.finalize()


class EncryptedSymAead(Tunnel):
    r"""
    Perform symmetrical AEAD encryption and decryption of the underlying stream before processing subcon. When parsing, entire stream is consumed. When building, it puts encrypted bytes and tag without marking the end.

    Parsing and building transforms all bytes using the selected cipher and also authenticates the `associated_data`. Since data is processed until EOF, it behaves similar to `GreedyBytes`. Size is undefined.

    The key for encryption and decryption should be passed via `contextkw` to `build` and `parse` methods.

    This construct is heavily based on the `cryptography` library, which supports the following AEAD ciphers. For more details please see the documentation of that library.

    AEAD ciphers:
    - AESGCM
    - AESCCM
    - ChaCha20Poly1305

    :param subcon: Construct instance, subcon used for storing the value
    :param cipher: Cipher object or context lambda from cryptography.hazmat.primitives.ciphers

    :raises ImportError: needed module could not be imported
    :raises StreamError: stream failed when reading until EOF
    :raises CipherError: unsupported cipher object is provided

    Can propagate cryptography.exceptions exceptions.

    Example::

        >>> from cryptography.hazmat.primitives.ciphers import aead
        >>> d = Struct(
        ...     "nonce" / Default(Bytes(16), os.urandom(16)),
        ...     "associated_data" / Bytes(21),
        ...     "enc_data" / EncryptedSymAead(
        ...         GreedyBytes,
        ...         lambda ctx: aead.AESGCM(ctx._.key),
        ...         this.nonce,
        ...         this.associated_data
        ...     )
        ... )
        >>> key128 = b"\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f"
        >>> d.build({"associated_data": b"This is authenticated", "enc_data": b"The secret message"}, key=key128)
        b'\xe3\xb0"\xbaQ\x18\xd3|\x14\xb0q\x11\xb5XZ\xeeThis is authenticated\x88~\xe5Vh\x00\x01m\xacn\xad k\x02\x13\xf4\xb4[\xbe\x12$\xa0\x7f\xfb\xbf\x82Ar\xb0\x97C\x0b\xe3\x85'
        >>> d.parse(b'\xe3\xb0"\xbaQ\x18\xd3|\x14\xb0q\x11\xb5XZ\xeeThis is authenticated\x88~\xe5Vh\x00\x01m\xacn\xad k\x02\x13\xf4\xb4[\xbe\x12$\xa0\x7f\xfb\xbf\x82Ar\xb0\x97C\x0b\xe3\x85', key=key128)
        Container:
            nonce = b'\xe3\xb0"\xbaQ\x18\xd3|\x14\xb0q\x11\xb5XZ\xee' (total 16)
            associated_data = b'This is authenti'... (truncated, total 21)
            enc_data = b'The secret messa'... (truncated, total 18)
    """

    def __init__(self, subcon, cipher, nonce, associated_data=b""):
        super().__init__(subcon)
        self.cipher = cipher
        self.nonce = nonce
        self.associated_data = associated_data

    def _evaluate_cipher(self, context, path):
        from cryptography.hazmat.primitives.ciphers.aead import (
            AESCCM,
            AESGCM,
            ChaCha20Poly1305,
        )

        cipher = evaluate(self.cipher, context)
        if not isinstance(cipher, (AESGCM, AESCCM, ChaCha20Poly1305)):
            raise CipherError(
                f"cipher object {repr(cipher)} is not supported", path=path
            )
        return cipher

    def _decode(self, data, context, path):
        cipher = self._evaluate_cipher(context, path)
        nonce = evaluate(self.nonce, context)
        associated_data = evaluate(self.associated_data, context)
        return cipher.decrypt(nonce, data, associated_data)

    def _encode(self, data, context, path):
        cipher = self._evaluate_cipher(context, path)
        nonce = evaluate(self.nonce, context)
        associated_data = evaluate(self.associated_data, context)
        return cipher.encrypt(nonce, data, associated_data)


class Rebuffered(Subconstruct):
    r"""
    Caches bytes from underlying stream, so it becomes seekable and tellable, and also becomes blocking on reading. Useful for processing non-file streams like pipes, sockets, etc.

    .. warning:: Experimental implementation. May not be mature enough.

    :param subcon: Construct instance, subcon which will operate on the buffered stream
    :param tailcutoff: optional, integer, amount of bytes kept in buffer, by default buffers everything

    Can also raise arbitrary exceptions in its implementation.

    Example::

        Rebuffered(..., tailcutoff=1024).parse_stream(nonseekable_stream)
    """

    def __init__(self, subcon, tailcutoff=None):
        super().__init__(subcon)
        self.stream2 = RebufferedBytesIO(None, tailcutoff=tailcutoff)

    def _parse(self, stream, context, path):
        self.stream2.substream = stream
        return self.subcon._parsereport(self.stream2, context, path)

    def _build(self, obj, stream, context, path):
        self.stream2.substream = stream
        return self.subcon._build(obj, self.stream2, context, path)
