"""
lazy equivalents
"""

import sys

from malstruct.lib import Container, ListContainer

from .core import Construct, Subconstruct
from .exceptions import *
from .helpers import stream_seek, stream_tell


class Lazy(Subconstruct):
    r"""
    Lazyfies a field.

    This wrapper allows you to do lazy parsing of individual fields inside a normal Struct (without using LazyStruct which may not work in every scenario). It is also used by KaitaiStruct compiler to emit `instances` because those are not processed greedily, and they may refer to other not yet parsed fields. Those are 2 entirely different applications but semantics are the same.

    Parsing saves the current stream offset and returns a lambda. If and when that lambda gets evaluated, it seeks the stream to then-current position, parses the subcon, and seeks the stream back to previous position. Building evaluates that lambda into an object (if needed), then defers to subcon. Size also defers to subcon.

    :param subcon: Construct instance

    :raises StreamError: requested reading negative amount, could not read enough bytes, requested writing different amount than actual data, or could not write all bytes
    :raises StreamError: stream is not seekable and tellable

    Example::

        >>> d = Lazy(Byte)
        >>> x = d.parse(b'\x00')
        >>> x
        <function malstruct.core.Lazy._parse.<locals>.execute>
        >>> x()
        0
        >>> d.build(0)
        b'\x00'
        >>> d.build(x)
        b'\x00'
        >>> d.sizeof()
        1
    """

    def __init__(self, subcon):
        super().__init__(subcon)

    def _parse(self, stream, context, path):
        offset = stream_tell(stream, path)

        def execute():
            fallback = stream_tell(stream, path)
            stream_seek(stream, offset, 0, path)
            obj = self.subcon._parsereport(stream, context, path)
            stream_seek(stream, fallback, 0, path)
            return obj

        len = self.subcon._actualsize(stream, context, path)
        stream_seek(stream, len, 1, path)
        return execute

    def _build(self, obj, stream, context, path):
        if callable(obj):
            obj = obj()
        return self.subcon._build(obj, stream, context, path)


class LazyContainer(dict):
    """Used internally."""

    def __init__(self, struct, stream, offsets, values, context, path):
        self._struct = struct
        self._stream = stream
        self._offsets = offsets
        self._values = values
        self._context = context
        self._path = path

    def __getattr__(self, name):
        if name in self._struct._subconsindexes:
            return self[name]
        raise AttributeError

    def __getitem__(self, index):
        if isinstance(index, str):
            index = self._struct._subconsindexes[index]  # KeyError
        if index in self._values:
            return self._values[index]
        stream_seek(self._stream, self._offsets[index], 0, self._path)  # KeyError
        parseret = self._struct.subcons[index]._parsereport(
            self._stream, self._context, self._path
        )
        self._values[index] = parseret
        return parseret

    def __len__(self):
        return len(self._struct.subcons)

    def keys(self):
        return iter(self._struct._subcons)

    def values(self):
        return (self[k] for k in self._struct._subcons)

    def items(self):
        return ((k, self[k]) for k in self._struct._subcons)

    __iter__ = keys

    def __eq__(self, other):
        return Container.__eq__(self, other)

    def __repr__(self):
        return "<LazyContainer: {} items cached, {} subcons>".format(
            len(self._values), len(self._struct.subcons)
        )


class LazyStruct(Construct):
    r"""
    Equivalent to :class:`~malstruct.core.Struct`, but when this class is parsed, most fields are not parsed (they are skipped if their size can be measured by _actualsize or _sizeof method). See its docstring for details.

    Fields are parsed depending on some factors:

    * Some fields like Int* Float* Bytes(5) Array(5,Byte) Pointer are fixed-size and are therefore skipped. Stream is not read.
    * Some fields like Bytes(this.field) are variable-size but their size is known during parsing when there is a corresponding context entry. Those fields are also skipped. Stream is not read.
    * Some fields like Prefixed PrefixedArray PascalString are variable-size but their size can be computed by partially reading the stream. Only first few bytes are read (the lengthfield).
    * Other fields like VarInt need to be parsed. Stream position that is left after the field was parsed is used.
    * Some fields may not work properly, due to the fact that this class attempts to skip fields, and parses them only out of necessity. Miscellaneous fields often have size defined as 0, and fixed sized fields are skippable.

    Note there are restrictions:

    * If a field like Bytes(this.field) references another field in the same struct, you need to access the referenced field first (to trigger its parsing) and then you can access the Bytes field. Otherwise it would fail due to missing context entry.
    * If a field references another field within inner (nested) or outer (super) struct, things may break. Context is nested, but this class was not rigorously tested in that manner.

    Building and sizeof are greedy, like in Struct.

    :param \*subcons: Construct instances, list of members, some can be anonymous
    :param \*\*subconskw: Construct instances, list of members (requires Python 3.6)
    """

    def __init__(self, *subcons, **subconskw):
        super().__init__()
        self.subcons = list(subcons) + list(k / v for k, v in subconskw.items())
        self._subcons = Container((sc.name, sc) for sc in self.subcons if sc.name)
        self._subconsindexes = Container(
            (sc.name, i) for i, sc in enumerate(self.subcons) if sc.name
        )
        self.flagbuildnone = all(sc.flagbuildnone for sc in self.subcons)

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
        offset = stream_tell(stream, path)
        offsets = {0: offset}
        values = {}
        for i, sc in enumerate(self.subcons):
            try:
                offset += sc._actualsize(stream, context, path)
                stream_seek(stream, offset, 0, path)
            except SizeofError:
                parseret = sc._parsereport(stream, context, path)
                values[i] = parseret
                if sc.name:
                    context[sc.name] = parseret
                offset = stream_tell(stream, path)
            offsets[i + 1] = offset
        return LazyContainer(self, stream, offsets, values, context, path)

    def _build(self, obj, stream, context, path):
        # exact copy from Struct class
        if obj is None:
            obj = Container()
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
        context.update(obj)
        for sc in self.subcons:
            try:
                if sc.flagbuildnone:
                    subobj = obj.get(sc.name, None)
                else:
                    subobj = obj[sc.name]  # raises KeyError

                if sc.name:
                    context[sc.name] = subobj

                buildret = sc._build(subobj, stream, context, path)
                if sc.name:
                    context[sc.name] = buildret
            except StopFieldError:
                break
        return context

    def _sizeof(self, context, path):
        # exact copy from Struct class
        context = Container(
            _=context,
            _params=context._params,
            _root=None,
            _parsing=context._parsing,
            _building=context._building,
            _sizing=context._sizing,
            _subcons=self._subcons,
            _io=None,
            _index=context.get("_index", None),
        )
        context._root = context._.get("_root", context)
        try:
            return sum(sc._sizeof(context, path) for sc in self.subcons)
        except (KeyError, AttributeError):
            raise SizeofError(
                "cannot calculate size, key not found in context", path=path
            )


class LazyListContainer(list):
    """Used internally."""

    def __init__(self, subcon, stream, count, offsets, values, context, path):
        self._subcon = subcon
        self._stream = stream
        self._count = count
        self._offsets = offsets
        self._values = values
        self._context = context
        self._path = path

    def __getitem__(self, index):
        if isinstance(index, slice):
            return [self[i] for i in range(*index.indices(self._count))]
        if index in self._values:
            return self._values[index]
        stream_seek(self._stream, self._offsets[index], 0, self._path)  # KeyError
        parseret = self._subcon._parsereport(self._stream, self._context, self._path)
        self._values[index] = parseret
        return parseret

    def __getslice__(self, start, stop):
        if stop == sys.maxsize:
            stop = self._count
        return self.__getitem__(slice(start, stop))

    def __len__(self):
        return self._count

    def __iter__(self):
        return (self[i] for i in range(self._count))

    def __eq__(self, other):
        return len(self) == len(other) and all(
            self[i] == other[i] for i in range(self._count)
        )

    def __repr__(self):
        return "<LazyListContainer: {} of {} items cached>".format(
            len(self._values), self._count
        )


class LazyArray(Subconstruct):
    r"""
    Equivalent to :class:`~malstruct.core.Array`, but the subcon is not parsed when possible (it gets skipped if the size can be measured by _actualsize or _sizeof method). See its docstring for details.

    Fields are parsed depending on some factors:

    * Some fields like Int* Float* Bytes(5) Array(5,Byte) Pointer are fixed-size and are therefore skipped. Stream is not read.
    * Some fields like Bytes(this.field) are variable-size but their size is known during parsing when there is a corresponding context entry. Those fields are also skipped. Stream is not read.
    * Some fields like Prefixed PrefixedArray PascalString are variable-size but their size can be computed by partially reading the stream. Only first few bytes are read (the lengthfield).
    * Other fields like VarInt need to be parsed. Stream position that is left after the field was parsed is used.
    * Some fields may not work properly, due to the fact that this class attempts to skip fields, and parses them only out of necessity. Miscellaneous fields often have size defined as 0, and fixed sized fields are skippable.

    Note there are restrictions:

    * If a field references another field within inner (nested) or outer (super) struct, things may break. Context is nested, but this class was not rigorously tested in that manner.

    Building and sizeof are greedy, like in Array.

    :param count: integer or context lambda, strict amount of elements
    :param subcon: Construct instance, subcon to process individual elements
    """

    def __init__(self, count, subcon):
        super().__init__(subcon)
        self.count = count

    def _parse(self, stream, context, path):
        sc = self.subcon
        count = self.count
        if callable(count):
            count = count(context)
        if not 0 <= count:
            raise RangeError("invalid count {}".format(count), path=path)
        offset = stream_tell(stream, path)
        offsets = {0: offset}
        values = {}
        for i in range(count):
            try:
                offset += sc._actualsize(stream, context, path)
                stream_seek(stream, offset, 0, path)
            except SizeofError:
                parseret = sc._parsereport(stream, context, path)
                values[i] = parseret
                offset = stream_tell(stream, path)
            offsets[i + 1] = offset
        return LazyListContainer(sc, stream, count, offsets, values, context, path)

    def _build(self, obj, stream, context, path):
        # exact copy from Array class
        count = self.count
        if callable(count):
            count = count(context)
        if not 0 <= count:
            raise RangeError("invalid count {}".format(count), path=path)
        if not len(obj) == count:
            raise RangeError(
                "expected %d elements, found %d" % (count, len(obj)), path=path
            )
        retlist = ListContainer()
        for i, e in enumerate(obj):
            context._index = i
            buildret = self.subcon._build(e, stream, context, path)
            retlist.append(buildret)
        return retlist

    def _sizeof(self, context, path):
        # exact copy from Array class
        try:
            count = self.count
            if callable(count):
                count = count(context)
        except (KeyError, AttributeError):
            raise SizeofError(
                "cannot calculate size, key not found in context", path=path
            )
        return count * self.subcon._sizeof(context, path)


class LazyBound(Construct):
    r"""
    Field that binds to the subcon only at runtime (during parsing and building, not ctor). Useful for recursive data structures, like linked-lists and trees, where a construct needs to refer to itself (while it does not exist yet in the namespace).

    Note that it is possible to obtain same effect without using this class, using a loop. However there are usecases where that is not possible (if remaining nodes cannot be sized-up, and there is data following the recursive structure). There is also a significant difference, namely that LazyBound actually does greedy parsing while the loop does lazy parsing. See examples.

    To break recursion, use `If` field. See examples.

    :param subconfunc: parameter-less lambda returning Construct instance, can also return itself

    Example::

        d = Struct(
            "value" / Byte,
            "next" / If(this.value > 0, LazyBound(lambda: d)),
        )
        >>> print(d.parse(b"\x05\x09\x00"))
        Container:
            value = 5
            next = Container:
                value = 9
                next = Container:
                    value = 0
                    next = None

    ::

        d = Struct(
            "value" / Byte,
            "next" / GreedyBytes,
        )
        data = b"\x05\x09\x00"
        while data:
            x = d.parse(data)
            data = x.next
            print(x)
        # print outputs
        Container:
            value = 5
            next = \t\x00 (total 2)
        # print outputs
        Container:
            value = 9
            next = \x00 (total 1)
        # print outputs
        Container:
            value = 0
            next =  (total 0)
    """

    def __init__(self, subconfunc):
        super().__init__()
        self.subconfunc = subconfunc

    def _parse(self, stream, context, path):
        sc = self.subconfunc()
        return sc._parsereport(stream, context, path)

    def _build(self, obj, stream, context, path):
        sc = self.subconfunc()
        return sc._build(obj, stream, context, path)
