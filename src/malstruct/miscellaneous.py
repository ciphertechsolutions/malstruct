"""
Miscellaneous constructs
"""

import binascii
import collections
import io
import os
import pickle
import re

from malstruct.lib import Container, ListContainer

from . import transforms
from .alignment import Pass
from .bytes_ import Bytes, GreedyBytes
from .core import (
    Adapter,
    Array,
    Construct,
    GreedyRange,
    Renamed,
    Sequence,
    Struct,
    Subconstruct,
    evaluate,
    this,
)
from .debug import Probe
from .exceptions import *
from .helpers import (
    singleton,
    stream_read,
    stream_read_entire,
    stream_seek,
    stream_tell,
)
from .strings import GreedyString, StringEncoded
from .transforms import NullTerminated


class Const(Subconstruct):
    r"""
    Field enforcing a constant. It is used for file signatures, to validate that the given pattern exists. Data in the stream must strictly match the specified value.

    Note that a variable sized subcon may still provide positive verification. Const does not consume a precomputed amount of bytes, but depends on the subcon to read the appropriate amount (eg. VarInt is acceptable). Whatever subcon parses into, gets compared against the specified value.

    Parses using subcon and return its value (after checking). Builds using subcon from nothing (or given object, if not None). Size is the same as subcon, unless it raises SizeofError.

    :param value: expected value, usually a bytes literal
    :param subcon: optional, Construct instance, subcon used to build value from, assumed to be Bytes if value parameter was a bytes literal

    :raises StreamError: requested reading negative amount, could not read enough bytes, requested writing different amount than actual data, or could not write all bytes
    :raises ConstError: parsed data does not match specified value, or building from wrong value
    :raises StringError: building from non-bytes value, perhaps unicode

    Example::

        >>> d = Const(b"IHDR")
        >>> d.build(None)
        b'IHDR'
        >>> d.parse(b"JPEG")
        malstruct.core.ConstError: expected b'IHDR' but parsed b'JPEG'

        >>> d = Const(255, Int32ul)
        >>> d.build(None)
        b'\xff\x00\x00\x00'
    """

    def __init__(self, value, subcon=None):
        if subcon is None:
            if not isinstance(value, bytes):
                raise StringError(
                    f"given non-bytes value {repr(value)}, perhaps unicode?"
                )
            subcon = Bytes(len(value))
        super().__init__(subcon)
        self.value = value
        self.flagbuildnone = True

    def _parse(self, stream, context, path):
        obj = self.subcon._parsereport(stream, context, path)
        if not obj == self.value:
            raise ConstError(
                f"parsing expected {repr(self.value)} but parsed {repr(obj)}", path=path
            )
        return obj

    def _build(self, obj, stream, context, path):
        if obj not in (None, self.value):
            raise ConstError(
                f"building expected None or {repr(self.value)} but got {repr(obj)}",
                path=path,
            )
        return self.subcon._build(self.value, stream, context, path)

    def _sizeof(self, context, path):
        return self.subcon._sizeof(context, path)


# Continuously parses until it hits the first non-zero byte.
SkipNull = Const(b"\x00")[:]


@singleton
class Index(Construct):
    r"""
    Indexes a field inside outer :class:`~malstruct.core.Array` :class:`~malstruct.core.GreedyRange` :class:`~malstruct.core.RepeatUntil` context.

    Note that you can use this class, or use `this._index` expression instead, depending on how its used. See the examples.

    Parsing and building pulls _index key from the context. Size is 0 because stream is unaffected.

    :raises IndexFieldError: did not find either key in context

    Example::

        >>> d = Array(3, Index)
        >>> d.parse(b"")
        [0, 1, 2]
        >>> d = Array(3, Struct("i" / Index))
        >>> d.parse(b"")
        [Container(i=0), Container(i=1), Container(i=2)]

        >>> d = Array(3, Computed(this._index+1))
        >>> d.parse(b"")
        [1, 2, 3]
        >>> d = Array(3, Struct("i" / Computed(this._._index+1)))
        >>> d.parse(b"")
        [Container(i=1), Container(i=2), Container(i=3)]
    """

    def __init__(self):
        super().__init__()
        self.flagbuildnone = True

    def _parse(self, stream, context, path):
        return context.get("_index", None)

    def _build(self, obj, stream, context, path):
        return context.get("_index", None)

    def _sizeof(self, context, path):
        return 0


class Default(Subconstruct):
    r"""
    Field where building does not require a value, because the value gets taken from default. Comes handy when building a Struct from a dict with missing keys.

    Parsing defers to subcon. Building is defered to subcon, but it builds from a default (if given object is None) or from given object. Building does not require a value, but can accept one. Size is the same as subcon, unless it raises SizeofError.

    Difference between Default and Rebuild, is that in first the build value is optional and in second the build value is ignored.

    :param subcon: Construct instance
    :param value: context lambda or constant value

    :raises StreamError: requested reading negative amount, could not read enough bytes, requested writing different amount than actual data, or could not write all bytes

    Can propagate any exception from the lambda, possibly non-ConstructError.

    Example::

        >>> d = Struct(
        ...     "a" / Default(Byte, 0),
        ... )
        >>> d.build(dict(a=1))
        b'\x01'
        >>> d.build(dict())
        b'\x00'
    """

    def __init__(self, subcon, value):
        super().__init__(subcon)
        self.value = value
        self.flagbuildnone = True

    def _build(self, obj, stream, context, path):
        obj = evaluate(self.value, context) if obj is None else obj
        return self.subcon._build(obj, stream, context, path)


class Check(Construct):
    r"""
    Checks for a condition, and raises CheckError if the check fails.

    Parsing and building return nothing (but check the condition). Size is 0 because stream is unaffected.

    :param func: bool or context lambda, that gets run on parsing and building

    :raises CheckError: lambda returned false

    Can propagate any exception from the lambda, possibly non-ConstructError.

    Example::

        Check(lambda ctx: len(ctx.payload.data) == ctx.payload_len)
        Check(len_(this.payload.data) == this.payload_len)
    """

    def __init__(self, func):
        super().__init__()
        self.func = func
        self.flagbuildnone = True

    def _parse(self, stream, context, path):
        passed = evaluate(self.func, context)
        if not passed:
            raise CheckError("check failed during parsing", path=path)

    def _build(self, obj, stream, context, path):
        passed = evaluate(self.func, context)
        if not passed:
            raise CheckError("check failed during building", path=path)

    def _sizeof(self, context, path):
        return 0


@singleton
class Error(Construct):
    r"""
    Raises ExplicitError, unconditionally.

    Parsing and building always raise ExplicitError. Size is undefined.

    :raises ExplicitError: unconditionally, on parsing and building

    Example::

        >>> d = Struct("num"/Byte, Error)
        >>> d.parse(b"data...")
        malstruct.core.ExplicitError: Error field was activated during parsing
    """

    def __init__(self):
        super().__init__()
        self.flagbuildnone = True

    def _parse(self, stream, context, path):
        raise ExplicitError("Error field was activated during parsing", path=path)

    def _build(self, obj, stream, context, path):
        raise ExplicitError("Error field was activated during building", path=path)

    def _sizeof(self, context, path):
        raise SizeofError(
            "Error does not have size, because it interrupts parsing and building",
            path=path,
        )


class ErrorMessage(Construct):
    r"""
    Raises an exception when triggered by parse or build. Can be used as a sentinel that blows a whistle when a conditional branch goes the wrong way, or to raise an error explicitly the declarative way.
    This modification allows the ability to supply a custom message.

    Example::

        >>> d = "x"/Int8sb >> IfThenElse(this.x > 0, Int8sb, ErrorMessage('Failed if statement'))
        >>> d.parse(b"\xff\x05")
        Traceback (most recent call last):
            ...
        construct.core.ExplicitError: Failed if statement
    """

    def __init__(self, message="Error field was activated."):
        super().__init__()
        self.message = message

    def _parse(self, stream, context, path):
        message = self.message(context) if callable(self.message) else self.message
        raise ExplicitError(message)

    def _build(self, obj, stream, context, path):
        message = self.message(context) if callable(self.message) else self.message
        raise ExplicitError(message)


# TODO: Should this be renamed to Map?
class Iter(Construct):
    r"""
    Class that allows iterating over an object and acting on each item.

    Example::

        >>> spec = Struct(
        ...     'types' / Byte[3],
        ...     'entries' / Iter(this.types, {
        ...        1: Int32ul,
        ...        2: Int16ul,
        ...     },
        ...     default=Pass
        ...     )
        ... )
        >>> spec.parse(b'\x01\x02\x09\x03\x03\x03\x03\x06\x06')
        Container(types=ListContainer([1, 2, 9]), entries=ListContainer([50529027, 1542, None]))
        >>> C = _
        >>> spec.build(C)
        b'\x01\x02\t\x03\x03\x03\x03\x06\x06'
        >>> spec.sizeof(**C)
        9

        >>> spec = Struct(
        ...     'sizes' / Int16ul[4],
        ...     'entries' / Iter(this.sizes, Bytes)  # equivalent to Iter(this.sizes, lambda size: Bytes(size))
        ... )
        >>> spec.parse(b'\x01\x00\x03\x00\x00\x00\x05\x00abbbddddd')
        Container(sizes=ListContainer([1, 3, 0, 5]), entries=ListContainer([b'a', b'bbb', b'', b'ddddd']))
        >>> C = _
        >>> spec.build(C)
        b'\x01\x00\x03\x00\x00\x00\x05\x00abbbddddd'
        >>> Iter(this.sizes, Bytes).sizeof(sizes=[1,2,3,0])
        6
        >>> spec.sizeof(**C)
        17

    :param iterable: iterable items to act upon
    :param cases: A dictionary of cases or a function that takes a key and returns a construct spec.
    :param default: The default case (only if cases is a dict)
    """

    def __init__(self, iterable, cases, default=None):
        super().__init__()
        self.iterable = iterable
        self.cases = cases
        self.default = default or Pass
        if not callable(cases):
            self.flagbuildnone = all(sc.flagbuildnone for sc in cases.values())
            if hasattr(self, "flagembedded"):
                self.flagembedded = all(sc.flagembedded for sc in cases.values())

    def _parse(self, stream, context, path):
        iterator = (
            iter(self.iterable(context))
            if callable(self.iterable)
            else iter(self.iterable)
        )
        if callable(self.cases):
            return ListContainer(
                [
                    self.cases(key)._parsereport(stream, context, path)
                    for key in iterator
                ]
            )
        else:
            return ListContainer(
                [
                    self.cases.get(key, self.default)._parsereport(
                        stream, context, path
                    )
                    for key in iterator
                ]
            )

    def _build(self, obj, stream, context, path):
        iterator = (
            iter(self.iterable(context))
            if callable(self.iterable)
            else iter(self.iterable)
        )
        for sub_obj, key in zip(obj, iterator):
            if callable(self.cases):
                self.cases(key)._build(sub_obj, stream, context, path)
            else:
                self.cases.get(key, self.default)._build(sub_obj, stream, context, path)

    def _sizeof(self, context, path):
        iterator = iter(evaluate(self.iterable, context))
        size = 0
        for key in iterator:
            try:
                if callable(self.cases):
                    size += self.cases(key)._sizeof(context, path)
                else:
                    size += self.cases.get(key, self.default)._sizeof(context, path)
            except (KeyError, AttributeError):
                raise SizeofError(
                    "cannot calculate size, {!r} key not found in context".format(key)
                )
        return size


@singleton
class Pickled(Construct):
    r"""
    Preserves arbitrary Python objects.

    Parses using `pickle.load() <https://docs.python.org/3/library/pickle.html#pickle.load>`_ and builds using `pickle.dump() <https://docs.python.org/3/library/pickle.html#pickle.dump>`_ functions, using default Pickle binary protocol. Size is undefined.

    :raises StreamError: requested reading negative amount, could not read enough bytes, requested writing different amount than actual data, or could not write all bytes

    Can propagate pickle.load() and pickle.dump() exceptions.

    Example::

        >>> x = [1, 2.3, {}]
        >>> Pickled.build(x)
        b'\x80\x03]q\x00(K\x01G@\x02ffffff}q\x01e.'
        >>> Pickled.parse(_)
        [1, 2.3, {}]
    """

    def _parse(self, stream, context, path):
        return pickle.load(stream)

    def _build(self, obj, stream, context, path):
        pickle.dump(obj, stream)
        return obj


@singleton
class Numpy(Construct):
    r"""
    Preserves numpy arrays (both shape, dtype and values).

    Parses using `numpy.load() <https://docs.scipy.org/doc/numpy/reference/generated/numpy.load.html#numpy.load>`_ and builds using `numpy.save() <https://docs.scipy.org/doc/numpy/reference/generated/numpy.save.html#numpy.save>`_ functions, using Numpy binary protocol. Size is undefined.

    :raises ImportError: numpy could not be imported during parsing or building
    :raises ValueError: could not read enough bytes, or so

    Can propagate numpy.load() and numpy.save() exceptions.

    Example::

        >>> import numpy
        >>> a = numpy.asarray([1,2,3])
        >>> Numpy.build(a)
        b"\x93NUMPY\x01\x00F\x00{'descr': '<i8', 'fortran_order': False, 'shape': (3,), }            \n\x01\x00\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00\x03\x00\x00\x00\x00\x00\x00\x00"
        >>> Numpy.parse(_)
        array([1, 2, 3])
    """

    def _parse(self, stream, context, path):
        import numpy

        return numpy.load(stream)

    def _build(self, obj, stream, context, path):
        import numpy

        numpy.save(stream, obj)
        return obj


class NamedTuple(Adapter):
    r"""
    Both arrays, structs, and sequences can be mapped to a namedtuple from `collections module <https://docs.python.org/3/library/collections.html#collections.namedtuple>`_. To create a named tuple, you need to provide a name and a sequence of fields, either a string with space-separated names or a list of string names, like the standard namedtuple.

    Parses into a collections.namedtuple instance, and builds from such instance (although it also builds from lists and dicts). Size is undefined.

    :param tuplename: string
    :param tuplefields: string or list of strings
    :param subcon: Construct instance, either Struct Sequence Array GreedyRange

    :raises StreamError: requested reading negative amount, could not read enough bytes, requested writing different amount than actual data, or could not write all bytes
    :raises NamedTupleError: subcon is neither Struct Sequence Array GreedyRange

    Can propagate collections exceptions.

    Example::

        >>> d = NamedTuple("coord", "x y z", Byte[3])
        >>> d = NamedTuple("coord", "x y z", Byte >> Byte >> Byte)
        >>> d = NamedTuple("coord", "x y z", "x"/Byte + "y"/Byte + "z"/Byte)
        >>> d.parse(b"123")
        coord(x=49, y=50, z=51)
    """

    def __init__(self, tuplename, tuplefields, subcon):
        if not isinstance(subcon, (Struct, Sequence, Array, GreedyRange)):
            raise NamedTupleError("subcon is neither Struct Sequence Array GreedyRange")
        super().__init__(subcon)
        self.tuplename = tuplename
        self.tuplefields = tuplefields
        self.factory = collections.namedtuple(tuplename, tuplefields)

    def _decode(self, obj, context, path):
        if isinstance(self.subcon, Struct):
            del obj["_io"]
            return self.factory(**obj)
        if isinstance(self.subcon, (Sequence, Array, GreedyRange)):
            return self.factory(*obj)
        raise NamedTupleError(
            "subcon is neither Struct Sequence Array GreedyRangeGreedyRange", path=path
        )

    def _encode(self, obj, context, path):
        if isinstance(self.subcon, Struct):
            return Container(
                {
                    sc.name: getattr(obj, sc.name)
                    for sc in self.subcon.subcons
                    if sc.name
                }
            )
        if isinstance(self.subcon, (Sequence, Array, GreedyRange)):
            return list(obj)
        raise NamedTupleError(
            "subcon is neither Struct Sequence Array GreedyRange", path=path
        )


# TODO: Add support for using a single construct for parsing an unknown number of times
# (or within a min, max, or exact)
# (Perhaps call it "Split" to avoid overloading too much functionality.)
# e.g.
# >>> spec = Delimited(b'|', GreedyString())
# >>> spec.parse(b'hello|world')
# ['hello', 'world']
# >>> spec.parse(b'hello|world|hi|bob')
# ['hello', 'world', 'hi', 'bob']
# >>> spec.parse(b'hello')
# ['hello']
class Delimited(Construct):
    r"""
    A construct used to parse delimited data.

    NOTE: The parsed constructs will be buffered

    Example::

        >>> spec = Delimited(b'|',
        ...     'first' / CString(),
        ...     'second' / Int32ul,
        ...     # When using a Greedy construct, either all data till EOF or the next delimiter will be consumed.
        ...     'third' / GreedyBytes,
        ...     'fourth' / Byte
        ... )
        >>> spec.parse(b'Hello\x00\x00|\x01\x00\x00\x00|world!!\x01\x02|\xff')
        Container(first=u'Hello', second=1, third=b'world!!\x01\x02', fourth=255)
        >>> spec.build(dict(first=u'Hello', second=1, third=b'world!!\x01\x02', fourth=255))
        b'Hello\x00|\x01\x00\x00\x00|world!!\x01\x02|\xff'

        # If you don't care about a particular element, you can leave it nameless just like in Structs.
        # NOTE: You can't build unless you have supplied every attribute.::

        >>> spec = Delimited(b'|',
        ...     'first' / CString(),
        ...     'second' / Int32ul,
        ...     Pass,
        ...     'fourth' / Byte
        ... )
        >>> spec.parse(b'Hello\x00\x00|\x01\x00\x00\x00|world!!\x01\x02|\xff')
        Container(first=u'Hello', second=1, fourth=255)

        # It may also be useful to use Pass or Optional for fields that may not exist.::

        >>> spec = Delimited(b'|',
        ...     'first' / CString(),
        ...     'second' / Pass,
        ...     'third' / Optional(Int32ul)
        ... )
        >>> spec.parse(b'Hello\x00\x00|dont care|\x01\x00\x00\x00')
        Container(first=u'Hello', second=None, third=1)
        >>> spec.parse(b'Hello\x00\x00||')
        Container(first=u'Hello', second=None, third=None)

        # delimiters may have a length > 1::

        >>> spec = Delimited(b'YOYO',
        ...     'first' / CString(),
        ...     'second' / Int32ul,
        ...     # When using a Greedy construct, either all data till EOF or the next delimiter will be consumed.
        ...     'third' / GreedyBytes,
        ...     'fourth' / Byte
        ... )
        >>> spec.parse(b'Hello\x00\x00YOYO\x01\x00\x00\x00YOYOworld!!YO!!\x01\x02YOYO\xff')
        Container(first=u'Hello', second=1, third=b'world!!YO!!\x01\x02', fourth=255)
        >>> spec.build(dict(first=u'Hello', second=1, third=b'world!!YO!!\x01\x02', fourth=255))
        b'Hello\x00YOYO\x01\x00\x00\x00YOYOworld!!YO!!\x01\x02YOYO\xff'

    """

    def __init__(self, delimiter, *subcons):
        """
        :param delimiter: single character or a function that takes context and returns the delimiter
        :param subcons: constructs to use to parse each element.
                    NOTE: The number of constructs will be the number of elements delimited.
                    (ie. len(subcons) == number of delimiters + 1)

        :raises ValueError: If no subcons are defined.
        """
        super().__init__()
        self.delimiter = delimiter
        self.subcons = subcons
        if len(subcons) < 2:
            raise ValueError("At least two subconstruct must be defined.")

    def _find_delimiter(self, stream, delimiter):
        """
        Finds given delimiter in stream.

        :returns: Stream offset for delimiter.
        :raises ConstructError: If delimiter isn't found.
        """
        fallback = stream.tell()
        try:
            for byte in iter(lambda: stream.read(1), b""):
                if delimiter[0] == ord(byte):
                    delimiter_offset = stream.seek(-1, os.SEEK_CUR)
                    if stream.read(len(delimiter)) == delimiter:
                        return delimiter_offset
                    else:
                        stream.seek(delimiter_offset + 1)
            raise ConstructError(f"Unable to find delimiter: {delimiter}")
        finally:
            stream.seek(fallback)

    def _parse_subcon(self, subcon, stream, obj, context, path):
        """Parses and fills obj and context."""
        subobj = subcon._parsereport(stream, context, path)
        if getattr(subcon, "flagembedded", False):
            if subobj is not None:
                obj.update(subobj.items())
                context.update(subobj.items())
        else:
            if subcon.name is not None:
                obj[subcon.name] = subobj
                context[subcon.name] = subobj

    def _parse(self, stream, context, path):
        delimiter = (
            self.delimiter(context) if callable(self.delimiter) else self.delimiter
        )
        if not isinstance(delimiter, bytes) or not delimiter:
            raise ValueError("Invalid delimiter.")

        obj = Container()
        context = Container(_=context)

        # Parse all but the last element.
        for sc in self.subcons[:-1]:
            # Don't count probes as an element.
            if isinstance(sc, Probe):
                sc._parsereport(stream, context, path)
                continue

            delimiter_offset = self._find_delimiter(stream, delimiter)

            # Temporarily fake the read() so that we can force EOF before delimiter.
            orig_read = stream.read

            def new_read(size=None):
                max_size = delimiter_offset - stream.tell()
                if size is None:
                    size = max_size
                else:
                    size = min(max_size, size)
                return orig_read(size)

            try:
                stream.read = new_read
                self._parse_subcon(sc, stream, obj, context, path)
            finally:
                stream.read = orig_read

            # Align to after delimiter
            stream.seek(delimiter_offset + len(delimiter))

        # Parse the last element.
        self._parse_subcon(self.subcons[-1], stream, obj, context, path)

        return obj

    def _build(self, obj, stream, context, path):
        delimiter = (
            self.delimiter(context) if callable(self.delimiter) else self.delimiter
        )
        if not isinstance(delimiter, bytes) or not delimiter:
            raise ValueError("Invalid delimiter.")

        context = Container(_=context)
        context.update(obj)
        for i, sc in enumerate(self.subcons):
            if getattr(sc, "flagembedded", False):
                subobj = obj
            elif sc.flagbuildnone:
                subobj = obj.get(sc.name, None)
            else:
                subobj = obj[sc.name]
            buildret = sc._build(subobj, stream, context, path)
            if buildret is not None:
                if getattr(sc, "flagembedded", False):
                    context.update(buildret)
                if sc.name is not None:
                    context[sc.name] = buildret
            # Add delimiter if not last element and not Probe.
            if i < len(self.subcons) - 1 and not isinstance(sc, Probe):
                stream.write(delimiter)
        return context


class Regex(Construct):
    r"""
    A construct designed look for the first match for the given regex, then parse the data collected in the groups.
    Returns the matched capture groups in attributes based on their respective names.
    If a subconstruct is defined for a group, it will run that construct on that particular piece of data.

    NOTE: The subconstruct will run on the data as if is the only data that exists. Therefore, using Seek and Tell
    will be purely relative to that piece of data only. This was done to ensure you are only parsing what has been
    captured. (If you need to use Seek or Tell, you will have to instead make a capture group that collects no data.)

    NOTE: If you supply a string as the regular expression, the re.DOTALL flag will be automatically specified.
    If you need to use different flags, you must past a compiled regex.

    Example::

        # The seek position is left at the end of the successful match (match.end()).
        >>> regex = re.compile(b'\x01\x02(?P<size>.{4})\x03\x04(?P<path>[A-Za-z].*\x00)', re.DOTALL)
        >>> data = b'GARBAGE!\x01\x02\x0A\x00\x00\x00\x03\x04C:\Windows\x00MORE GARBAGE!'
        >>> r = Regex(regex, size=Int32ul, path=CString()).parse(data)
        >>> r == Container(path='C:\\Windows', size=10)
        True
        >>> r = Regex(regex).parse(data)
        >>> r == Container(path=b'C:\\Windows\x00', size=b'\n\x00\x00\x00')
        True
        >>> r = Struct(
        ...     're' / Regex(regex, size=Int32ul, path=CString()),
        ...     'after_re' / Tell,
        ...     'garbage' / GreedyBytes
        ... ).parse(data)
        >>> r == Container(re=Container(path='C:\\Windows', size=10), after_re=27, garbage=b'MORE GARBAGE!')
        True

        >>> Struct(
        ...     *Regex(regex, size=Int32ul, path=CString()),
        ...     'after_re' / Tell,
        ...     'garbage' / GreedyBytes
        ... ).parse(data)
        Container(size=10, path=u'C:\\Windows', after_re=27, garbage=b'MORE GARBAGE!')

        # You can use Regex as a trigger to find a particular piece of data before you start parsing.
        >>> Struct(
        ...     Regex(b'TRIGGER'),
        ...     'greeting' / CString()
        ... ).parse(b'\x01\x02\x04GARBAGE\x05TRIGGERhello world\x00')
        Container(greeting=u'hello world')

        # If no data is captured, the associated subcon will received a stream with the position set at the location
        # of that captured group. Thus, allowing you to use it as an anchor point.
        >>> r = Regex(b'hello (?P<anchor>)world(?P<extra_data>.*)', anchor=Tell).parse(b'hello world!!!!')
        >>> r == Container(extra_data=b'!!!!', anchor=6)
        True

        # If no named capture groups are used, you can instead parse the entire matched string by supplying
        # a subconstruct as a positional argument. (If no subcon is provided, the raw bytes are returned instead.
        >>> Regex(b'hello world\x00', CString()).parse(b'GARBAGE\x01\x03hello world\x00\x04')
        'hello world'
        >>> Regex(b'hello world\x00').parse(b'GARBAGE\x01\x03hello world\x00\x04')
        b'hello world\x00'

        # You can also set the regular expression to match in-place (instead of searching the data)
        # by setting the keyword argument _match to True.

        >>> Regex('hello', _match=True).parse(b'hello world!')
        b'hello'
        >>> Regex('hello').parse(b'bogus hello world')
        b'hello'
        >>> Regex('hello', _match=True).parse(b'bogus hello world')
        Traceback (most recent call last):
            ...
        construct.core.ConstructError: [(parsing)] regex did not match
    """

    __slots__ = ["regex", "subcon", "subcons", "match"]

    def __init__(self, regex, *subcon, **group_subcons):
        """
        Initializes regex construct.

        :param regex: A regex to use (can be a string or compiled).
        :param subcon:
            A subcon to use on the entire matching string when there are no named capture groups.
            (NOTE: This is only used if there are no capture groups.
            If you want to use capture groups AND this then have a capture group encapsulating the entire regex.)
        :param group_subcons:
            Keyword argument dictionary that contains the constructs to use for the corresponding capture group.
            If a subcon is not supplied for a capture group, it will default to returning bytes
            (equivalent to setting construct.Bytes() for that group.)

        :raises ValueError: If arguments are invalid.
        """
        super().__init__()
        if isinstance(regex, str):
            regex = regex.encode()  # force byte strings
        if isinstance(regex, bytes):
            regex = re.compile(regex, re.DOTALL)
        self.regex = regex
        self.match = group_subcons.pop("_match", False)
        self.subcons = [Renamed(sc, name) for name, sc in group_subcons.items()]
        self._subcons = Container((sc.name, sc) for sc in self.subcons)
        if subcon and len(subcon) > 1:
            raise ValueError("Only one subcon can be supplied for the entire match.")
        if subcon and group_subcons:
            raise ValueError(
                "subcon and group_subcons arguments cannot be used at the same time."
            )
        self.subcon = subcon[0] if subcon else None

    def __getattr__(self, name):
        if name in self._subcons:
            return self._subcons[name]
        raise AttributeError

    def _parse(self, stream, context, path):
        start = stream.tell()
        # NOTE: we are going to have to read the entire stream due to regex requirements.
        # However, that's okay in this case since we are parsing ByteIO anyway.
        if self.match:
            match = self.regex.match(stream.read())
        else:
            match = self.regex.search(stream.read())
        if not match:
            raise ConstructError(f"[{path}] regex did not match")

        try:
            group_dict = match.groupdict()

            # If there are no named groups. Return parsed full match instead.
            if not group_dict:
                if self.subcon:
                    sub_stream = io.BytesIO(match.group())
                    return self.subcon._parsereport(sub_stream, context, path)
                else:
                    return match.group()

            # Otherwise, we are going to parse each named capture group.
            obj = Container()
            obj._io = stream

            context = Container(
                _=context,
                _params=context._params,
                _root=None,
                _parsing=context._parsing,
                _building=context._building,
                _sizing=context._sizing,
                _subcons=self.subcons,
                _io=stream,
                _index=context.get("_index", None),
            )
            context._root = context._.get("_root", context)

            # Default to displaying matched data as pure bytes.
            obj.update(group_dict)
            context.update(group_dict)

            # Parse groups using supplied constructs.
            for subcon in self.subcons:
                name = subcon.name
                try:
                    data = match.group(name)
                except IndexError:
                    continue

                # If data is None, then we are most likely dealing with an optional capture group.
                if data is None:
                    obj[name] = None
                    context[name] = None
                    continue

                # If we have an empty capture group, the user would like to use it as an anchor.
                if not data:
                    stream.seek(start + match.start(name))
                    sub_stream = stream
                else:
                    sub_stream = io.BytesIO(data)

                try:
                    subobj = subcon._parsereport(sub_stream, context, path)
                except ConstructError as e:
                    # Raise a more useful error message.
                    # TODO: Remove when path is provided in exception messages.
                    raise ConstructError(
                        "Failed to parse {} capture group with error: {}".format(
                            name, e
                        )
                    )
                obj[name] = subobj
                context[name] = subobj
            return obj

        finally:
            # Reset position to right after the matched regex.
            stream.seek(start + match.end())

    def _build(self, obj, stream, context, path):
        raise ConstructError("Building for Regex is not supported.")

    def _sizeof(self, context, path):
        raise SizeofError("sizeof() for Regex is not supported.")


def RegexSearch(regex, *subcon, **group_subcons) -> Regex:
    """Performs search of given regex pattern starting at current stream position and then parses match groups."""
    return Regex(regex, *subcon, _match=False, **group_subcons)


def RegexMatch(regex, *subcon, **group_subcons) -> Regex:
    """Peforms match of given regex pattern at current stream position and then parses match groups."""
    return Regex(regex, *subcon, _match=True, **group_subcons)


class BytesTerminated(NullTerminated):
    r"""
    BytesTerminated is the same as NullTerminated except that it is targeted for binary data and not strings, and
    therefore the terminator can be an arbitrary length (as opposed to having length equal to the character width).
    See the NullTerminated documentation for the remainder of the functionality and options.

    >>> BytesTerminated(GreedyBytes, term=b'TERM').parse(b'helloTERM')
    b'hello'
    """

    # The only method we need to override is _parse. Everything else from NullTerminated works as-is.
    def _parse(self, stream, context, path):
        term = self.term
        term_len = len(term)
        if term_len < 1:
            raise PaddingError("BytesTerminated term must be at least 1 byte")
        data = b""
        while True:
            pos = stream_tell(stream, path)
            try:
                b = stream_read(stream, term_len)
                stream_seek(stream, pos, 0, path)
            except StreamError:
                if self.require:
                    raise
                else:
                    stream_seek(stream, pos, 0, path)
                    data += stream_read_entire(stream)
                    break

            if b == term:
                if self.include:
                    data += b
                if self.consume:
                    stream_read(stream, term_len, path)
                break
            else:
                data += stream_read(stream, 1, path)
        if self.subcon is GreedyBytes:
            return data
        if type(self.subcon) is GreedyString:
            return data.decode(self.subcon.encoding)
        return self.subcon._parsereport(io.BytesIO(data), context, path)


class Stripped(Adapter):
    r"""
    An adapter that strips characters/bytes from the right of the parsed results.

    NOTE: While this may look similar to Padded() this is different because this
    doesn't take a length and instead strips out the nulls from within the already parsed subconstruct.

    :param subcon: The sub-construct to wrap.
    :param pad: The character/bytes to use for stripping. Defaults to null character.

    Example::

        >>> Stripped(GreedyBytes).parse(b'hello\x00\x00\x00')
        b'hello'
        >>> Stripped(Bytes(10)).parse(b'hello\x00\x00\x00\x00\x00')
        b'hello'
        >>> Stripped(Bytes(14), pad=b'PAD').parse(b'helloPADPADPAD')
        b'hello'
        >>> Stripped(Bytes(14), pad=b'PAD').build(b'hello')
        b'helloPADPADPAD'
        >>> Stripped(CString(), pad=u'PAD').parse(b'helloPADPAD\x00')
        'hello'
        >>> Stripped(String(14), pad=u'PAD').parse(b'helloPADPAD\x00\x00\x00')
        'hello'

        # WARNING: If padding doesn't fit in the perscribed data it will not strip it!
        >>> Stripped(Bytes(13), pad=b'PAD').parse(b'helloPADPADPA')
        b'helloPADPADPA'
        >>> Stripped(Bytes(13), pad=b'PAD').build(b'hello')
        Traceback (most recent call last):
            ...
        construct.core.StreamError: Error in path (building)
        bytes object of wrong length, expected 13, found 5

        # If the wrapped subconstruct's size can't be determined, if defaults to not providing a pad.
        >>> Stripped(CString(), pad=u'PAD').build(u'hello')
        b'hello\x00'
    """

    def __init__(self, subcon, pad=None):
        super().__init__(subcon)
        self.pad = pad

    def _decode(self, obj, context, path):
        pad = self.pad

        if pad is None:
            pad = "\0" if isinstance(obj, str) else b"\x00"

        if not isinstance(pad, type(obj)):
            raise PaddingError(
                f"NullStripped pad must be of the same type: {type(pad)} vs {type(obj)}"
            )

        unit = len(pad)
        if unit < 1:
            raise PaddingError("NullStripped pad must be at least 1 byte")

        obj = obj
        if unit == 1:
            obj = obj.rstrip(pad)
        else:
            tailunit = len(obj) % unit
            end = len(obj)
            if tailunit and obj[-tailunit:] == pad[:tailunit]:
                end -= tailunit
            while end - unit >= 0 and obj[end - unit : end] == pad:
                end -= unit
            obj = obj[:end]

        return obj

    def _encode(self, obj, context, path):
        pad = self.pad

        if pad is None:
            pad = "\0" if isinstance(self.subcon, StringEncoded) else b"\x00"

        try:
            size = self.subcon._sizeof(context, path)
        except SizeofError:
            return obj  # Don't pad if we can't figure out size.

        unit = len(pad)
        if unit == 1:
            obj = obj.ljust(size, pad)
        # Only pad if it fits in nicely.
        elif (size - len(obj)) % unit == 0:
            obj = (obj + (pad * (size - len(obj))))[:size]

        return obj


class Base64(Adapter):
    r"""
    Adapter used to Base64 encoded/decode a value.

    WARNING: This adapter must be used on a unicode string value.

    :param subcon: the construct to wrap
    :param custom_alpha: optional custom alphabet to use

    Example::

        >>> Base64(GreedyString()).build(b'hello')
        b'aGVsbG8='
        >>> Base64(GreedyString()).parse(b'aGVsbG8=')
        b'hello'
        >>> Base64(GreedyBytes).build(b'\x01\x02\x03\x04')
        b'AQIDBA=='
        >>> Base64(GreedyBytes).parse(b'AQIDBA==')
        b'\x01\x02\x03\x04'

    NOTE: String size is based on the encoded version.

        >>> Base64(String(16)).build('hello world')
        b'aGVsbG8gd29ybGQ='
        >>> Base64(String(16)).parse(b'aGVsbG8gd29ybGQ=')
        b'hello world'

    Supplying a custom alphabet is also supported.

        >>> spec = Base64(String(16), custom_alpha=b'EFGHQRSTUVWefghijklmnopIJKLMNOPABCDqrstuvwxyXYZabcdz0123456789+/=')
        >>> spec.build('hello world')
        b'LSoXMS8BO29dMSj='
        >>> spec.parse(b'LSoXMS8BO29dMSj=')
        b'hello world'
    """

    def __init__(self, subcon, custom_alpha=None):
        super().__init__(subcon)
        self.custom_alpha = custom_alpha

    def _encode(self, obj, context, path):
        from malstruct.lib import custombase64

        obj = custombase64.b64encode(obj, alphabet=self.custom_alpha)
        # Convert to unicode if wrapped subcon expects it.
        if isinstance(self.subcon, StringEncoded):
            obj = obj.decode("utf-8")
        return obj

    def _decode(self, obj, context, path):
        from malstruct.lib import custombase64

        if isinstance(obj, str):
            obj = obj.encode("utf-8")
        try:
            return custombase64.b64decode(obj, alphabet=self.custom_alpha)
        except binascii.Error as e:
            raise ConstructError(f"[{path}] {e}")


class Backwards(Subconstruct):
    r"""
    Subconstruct used to parse a given subconstruct backwards in the stream.
    This ia a macro for seeking backwards before parsing the construct.
    (This will not work for subcons that don't have a valid sizeof.
    Except for GreedyBytes and GreedyString)

    The stream will be left off at the start of the parsed result by design.
    Therefore, doing something like Int32ul >> Backwards(Int32ul) >> Int32ul will parse
    the same data 3 times.

    Example::

        >>> (Bytes(14) >> Backwards(Int32ul) >> Tell).parse(b'junk stuff\x01\x02\x00\x00')
        ListContainer([b'junk stuff\x01\x02\x00\x00', 513, 10])
        >>> spec = Struct(Seek(0, os.SEEK_END), 'name' / Backwards(String(9)), 'number' / Backwards(Int32ul))
        >>> spec.parse(b'A BUNCH OF JUNK DATA\x01\x00\x00\x00joe shmoe')
        Container(name=u'joe shmoe', number=1)

        # WARNING: This will break if the subcon doesn't have a valid sizeof.
        >>> spec = Struct(Seek(0, os.SEEK_END), 'name' / Backwards(CString()), 'number' / Backwards(Int32ul))
        >>> spec.parse(b'A BUNCH OF JUNK DATA\x01\x00\x00\x00joe shmoe\x00')
        Traceback (most recent call last):
          ...
        construct.core.SizeofError: Error in path (parsing) -> name
        <BLANKLINE>

        # However, GreedyBytes and GreedyString are allowed.
        >>> spec = Struct(Seek(0, os.SEEK_END), 'name' / Backwards(String(9)), 'rest' / Backwards(GreedyBytes))
        >>> spec.parse(b'A BUNCH OF JUNK DATA\x01\x00\x00\x00joe shmoe')
        Container(name=u'joe shmoe', rest=b'A BUNCH OF JUNK DATA\x01\x00\x00\x00')
        >>> spec = Struct(Seek(0, os.SEEK_END), 'name' / Backwards(String(9)), 'rest' / Backwards(GreedyString(encoding='utf-16-le')))
        >>> spec.parse(b'h\x00e\x00l\x00l\x00o\x00joe shmoe')
        Container(name=u'joe shmoe', rest=u'hello')

        # WARNING: This will also break if you read more data that is behind the current position.
        >>> (Seek(0, os.SEEK_END) >> Backwards(String(10))).parse(b'yo')
        Traceback (most recent call last):
          ...
        construct.core.FormatFieldError: could not read enough bytes, expected 10, found 2
    """

    def __init__(self, subcon):
        super().__init__(subcon)
        # GreedyBytes and GreedyString are allowed special cases.
        self.greedy = self.subcon is GreedyBytes or (
            isinstance(self.subcon, StringEncoded) and self.subcon.subcon is GreedyBytes
        )

    def _parse(self, stream, context, path):
        # Seek back to start of subcon.
        orig_pos = stream.tell()
        if self.greedy:
            start_pos = stream.seek(0)
            size = orig_pos - start_pos
            try:
                sub_stream = io.BytesIO(stream_read(stream, size))
                return self.subcon._parsereport(sub_stream, context, path)
            finally:
                stream.seek(start_pos)
        else:
            size = self.subcon._sizeof(context, path)
            start_pos = stream.seek(size * -1, os.SEEK_CUR)
            # Determine if we fell off the front.
            if orig_pos - start_pos < size:
                raise FormatFieldError(
                    "could not read enough bytes, expected %d, found %d"
                    % (size, orig_pos - start_pos)
                )
            try:
                return self.subcon._parsereport(stream, context, path)
            finally:
                stream.seek(start_pos)

    def _build(self, obj, stream, context, path):
        # TODO: Add support for building.
        raise NotImplementedError("Building is not supported.")


# Monkey patch RawCopy so that it can handle when we read the stream backwards.
def _parse(self, stream, context, path):
    offset1 = stream.tell()
    obj = self.subcon._parsereport(stream, context, path)
    offset2 = stream.tell()
    # Swap if subcon read backwards.
    if offset1 > offset2:
        offset1, offset2 = offset2, offset1
    fallback = stream.tell()
    stream_seek(stream, offset1, 0, path)
    data = stream_read(stream, offset2 - offset1, path)
    stream.seek(fallback)
    return Container(
        data=data,
        value=obj,
        offset1=offset1,
        offset2=offset2,
        length=(offset2 - offset1),
    )


transforms.RawCopy._parse = _parse
