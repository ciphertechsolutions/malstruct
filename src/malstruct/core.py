"""
Internal methods, abstract constructs, structures, sequences, and arrays
"""

import collections
import io
import itertools
import sys
import uuid

from malstruct.lib import Container, ListContainer

from .exceptions import *
from .expr import this
from .helpers import stream_read_entire, stream_seek, stream_tell, stream_write


def mergefields(*subcons):
    def select(sc):
        # If it quacks like a duck...
        if hasattr(sc, "subcons"):
            return sc.subcons
        elif hasattr(sc, "subcon"):
            return select(sc.subcon)
        raise ConstructError(
            "Embedding only works with: Struct Sequence FocusedSeq Union LazyStruct: {!r}".format(
                sc
            )
        )

    result = []
    for sc in subcons:
        if sc.flagembedded:
            result.extend(select(sc))
        else:
            result.append(sc)
    return result


def _obtain_subcons(subcon):
    while isinstance(subcon, Subconstruct):
        subcon = subcon.subcon
    return getattr(subcon, "subcons", [])


def _embed(subcon):
    # Peel back any layers to reveal the nested subcons.
    subcons = _obtain_subcons(subcon)

    # Ignore and just yield the original subcon if we don't find any nested subcons.
    if not subcons:
        yield subcon
        return

    # Discover name.
    if subcon.name:
        name = subcon.name
    else:
        name = f"_embed_{uuid.uuid4().hex}"
        subcon = name / subcon

    yield subcon
    for nested in subcons:
        if nested.name:
            yield nested.name / Computed(
                lambda ctx, root_name=name, nested_name=nested.name: ctx[root_name][
                    nested_name
                ]
            )


def hyphenatedict(d):
    return {k.replace("_", "-").rstrip("-"): v for k, v in d.items()}


def hyphenatelist(l):
    return [hyphenatedict(d) for d in l]


def extractfield(sc):
    if isinstance(sc, Renamed):
        return extractfield(sc.subcon)
    return sc


def evaluate(param, context):
    return param(context) if callable(param) else param


class Construct:
    r"""
    The mother of all constructs.

    This object is generally not directly instantiated, and it does not directly implement parsing and building, so it is largely only of interest to subclass implementors. There are also other abstract classes sitting on top of this one.

    The external user API:

    * `parse`
    * `parse_stream`
    * `parse_file`
    * `build`
    * `build_stream`
    * `build_file`
    * `sizeof`
    * `compile`
    * `benchmark`

    Subclass authors should not override the external methods. Instead, another API is available:

    * `_parse`
    * `_build`
    * `_sizeof`
    * `_actualsize`
    * `_emitparse`
    * `_emitbuild`
    * `_emitseq`
    * `_emitprimitivetype`
    * `_emitfulltype`
    * `__getstate__`
    * `__setstate__`

    Attributes and Inheritance:

    All constructs have a name and flags. The name is used for naming struct members and context dictionaries. Note that the name can be a string, or None by default. A single underscore "_" is a reserved name, used as up-level in nested containers. The name should be descriptive, short, and valid as a Python identifier, although these rules are not enforced. The flags specify additional behavioral information about this construct. Flags are used by enclosing constructs to determine a proper course of action. Flags are often inherited from inner subconstructs but that depends on each class.
    """

    def __init__(self):
        self.name = None
        self.docs = ""
        self.flagbuildnone = False
        self.parsed = None

    def __repr__(self):
        return "<{}{}{}{}>".format(
            self.__class__.__name__,
            " " + self.name if self.name else "",
            " +nonbuild" if self.flagbuildnone else "",
            " +docs" if self.docs else "",
        )

    def __getstate__(self):
        attrs = {}
        if hasattr(self, "__dict__"):
            attrs.update(self.__dict__)
        slots = []
        c = self.__class__
        while c is not None:
            if hasattr(c, "__slots__"):
                slots.extend(c.__slots__)
            c = c.__base__
        for name in slots:
            if hasattr(self, name):
                attrs[name] = getattr(self, name)
        return attrs

    def __setstate__(self, attrs):
        for name, value in attrs.items():
            setattr(self, name, value)

    def __copy__(self):
        self2 = object.__new__(self.__class__)
        self2.__setstate__(self.__getstate__())
        return self2

    def __iter__(self):
        yield from _embed(self)

    def parse(self, data, **contextkw):
        r"""
        Parse an in-memory buffer (often bytes object). Strings, buffers, memoryviews, and other complete buffers can be parsed with this method.

        Whenever data cannot be read, ConstructError or its derivative is raised. This method is NOT ALLOWED to raise any other exceptions although (1) user-defined lambdas can raise arbitrary exceptions which are propagated (2) external libraries like numpy can raise arbitrary exceptions which are propagated (3) some list and dict lookups can raise IndexError and KeyError which are propagated.

        Context entries are passed only as keyword parameters \*\*contextkw.

        :param \*\*contextkw: context entries, usually empty

        :returns: some value, usually based on bytes read from the stream but sometimes it is computed from nothing or from the context dictionary, sometimes its non-deterministic

        :raises ConstructError: raised for any reason
        """
        return self.parse_stream(io.BytesIO(data), **contextkw)

    def parse_stream(self, stream, **contextkw):
        r"""
        Parse a stream. Files, pipes, sockets, and other streaming sources of data are handled by this method. See parse().
        """
        context = Container(**contextkw)
        context._parsing = True
        context._building = False
        context._sizing = False
        context._params = context
        try:
            return self._parsereport(stream, context, "(parsing)")
        except CancelParsing:
            pass

    def parse_file(self, filename, **contextkw):
        r"""
        Parse a closed binary file. See parse().
        """
        with open(filename, "rb") as f:
            return self.parse_stream(f, **contextkw)

    def _parsereport(self, stream, context, path):
        obj = self._parse(stream, context, path)
        if self.parsed is not None:
            self.parsed(obj, context)
        return obj

    def _parse(self, stream, context, path):
        """Override in your subclass."""
        raise NotImplementedError

    def build(self, obj, **contextkw):
        r"""
        Build an object in memory (a bytes object).

        Whenever data cannot be written, ConstructError or its derivative is raised. This method is NOT ALLOWED to raise any other exceptions although (1) user-defined lambdas can raise arbitrary exceptions which are propagated (2) external libraries like numpy can raise arbitrary exceptions which are propagated (3) some list and dict lookups can raise IndexError and KeyError which are propagated.

        Context entries are passed only as keyword parameters \*\*contextkw.

        :param \*\*contextkw: context entries, usually empty

        :returns: bytes

        :raises ConstructError: raised for any reason
        """
        stream = io.BytesIO()
        self.build_stream(obj, stream, **contextkw)
        return stream.getvalue()

    def build_stream(self, obj, stream, **contextkw):
        r"""
        Build an object directly into a stream. See build().
        """
        context = Container(**contextkw)
        context._parsing = False
        context._building = True
        context._sizing = False
        context._params = context
        self._build(obj, stream, context, "(building)")

    def build_file(self, obj, filename, **contextkw):
        r"""
        Build an object into a closed binary file. See build().
        """
        # Open the file for reading as well as writing. This allows builders to
        # read back the stream just written. For example. RawCopy does this.
        # See issue #888.
        with open(filename, "w+b") as f:
            self.build_stream(obj, f, **contextkw)

    def _build(self, obj, stream, context, path):
        """Override in your subclass."""
        raise NotImplementedError

    def sizeof(self, **contextkw):
        r"""
        Calculate the size of this object, optionally using a context.

        Some constructs have fixed size (like FormatField), some have variable-size and can determine their size given a context entry (like Bytes(this.otherfield1)), and some cannot determine their size (like VarInt).

        Whenever size cannot be determined, SizeofError is raised. This method is NOT ALLOWED to raise any other exception, even if eg. context dictionary is missing a key, or subcon propagates ConstructError-derivative exception.

        Context entries are passed only as keyword parameters \*\*contextkw.

        :param \*\*contextkw: context entries, usually empty

        :returns: integer if computable, SizeofError otherwise

        :raises SizeofError: size could not be determined in actual context, or is impossible to be determined
        """
        context = Container(**contextkw)
        context._parsing = False
        context._building = False
        context._sizing = True
        context._params = context
        return self._sizeof(context, "(sizeof)")

    def _sizeof(self, context, path):
        """Override in your subclass."""
        raise SizeofError(path=path)

    def _actualsize(self, stream, context, path):
        return self._sizeof(context, path)

    def __rtruediv__(self, name):
        """
        Used for renaming subcons, usually part of a Struct, like Struct("index" / Byte).
        """
        return Renamed(self, newname=name)

    __rdiv__ = __rtruediv__

    def __mul__(self, other):
        """
        Used for adding docstrings and parsed hooks to subcons, like "field" / Byte * "docstring" * processfunc.
        """
        if isinstance(other, str):
            return Renamed(self, newdocs=other)
        if callable(other):
            return Renamed(self, newparsed=other)
        raise ConstructError("operator * can only be used with string or lambda")

    def __rmul__(self, other):
        """
        Used for adding docstrings and parsed hooks to subcons, like "field" / Byte * "docstring" * processfunc.
        """
        if isinstance(other, str):
            return Renamed(self, newdocs=other)
        if callable(other):
            return Renamed(self, newparsed=other)
        raise ConstructError("operator * can only be used with string or lambda")

    def __add__(self, other):
        """
        Used for making Struct like ("index"/Byte + "prefix"/Byte).
        """
        lhs = self.subcons if isinstance(self, Struct) else [self]
        rhs = other.subcons if isinstance(other, Struct) else [other]
        return Struct(*(lhs + rhs))

    def __rshift__(self, other):
        """
        Used for making Sequences like (Byte >> Short).
        """
        lhs = self.subcons if isinstance(self, Sequence) else [self]
        rhs = other.subcons if isinstance(other, Sequence) else [other]
        return Sequence(*(lhs + rhs))

    def __getitem__(self, count):
        """
        Used for making Arrays like Byte[5] and Byte[this.count].
        """
        if isinstance(count, slice):
            if count.step is not None:
                raise ValueError("slice must not contain a step: %r" % count)
            min = 0 if count.start is None else count.start
            max = sys.maxsize if count.stop is None else count.stop
            return Range(min, max, self)
        if isinstance(count, int) or callable(count):
            return Array(count, self)
        raise ConstructError("subcon[N] syntax expects integer or context lambda")


class Subconstruct(Construct):
    r"""
    Abstract subconstruct (wraps an inner construct, inheriting its name and flags). Parsing and building is by default deferred to subcon, same as sizeof.

    :param subcon: Construct instance
    """

    def __init__(self, subcon):
        if not isinstance(subcon, Construct):
            raise TypeError("subcon should be a Construct field")
        super().__init__()
        self.subcon = subcon
        self.flagbuildnone = subcon.flagbuildnone

    def __repr__(self):
        return "<{}{}{}{} {}>".format(
            self.__class__.__name__,
            " " + self.name if self.name else "",
            " +nonbuild" if self.flagbuildnone else "",
            " +docs" if self.docs else "",
            repr(self.subcon),
        )

    def _parse(self, stream, context, path):
        return self.subcon._parsereport(stream, context, path)

    def _build(self, obj, stream, context, path):
        return self.subcon._build(obj, stream, context, path)

    def _sizeof(self, context, path):
        return self.subcon._sizeof(context, path)


class Adapter(Subconstruct):
    r"""
    Abstract adapter class.

    Needs to implement `_decode()` for parsing and `_encode()` for building.

    :param subcon: Construct instance
    """

    def _parse(self, stream, context, path):
        obj = self.subcon._parsereport(stream, context, path)
        return self._decode(obj, context, path)

    def _build(self, obj, stream, context, path):
        obj2 = self._encode(obj, context, path)
        buildret = self.subcon._build(obj2, stream, context, path)
        return obj

    def _decode(self, obj, context, path):
        raise NotImplementedError

    def _encode(self, obj, context, path):
        raise NotImplementedError


class SymmetricAdapter(Adapter):
    r"""
    Abstract adapter class.

    Needs to implement `_decode()` only, for both parsing and building.

    :param subcon: Construct instance
    """

    def _encode(self, obj, context, path):
        return self._decode(obj, context, path)


class Validator(SymmetricAdapter):
    r"""
    Abstract class that validates a condition on the encoded/decoded object.

    Needs to implement `_validate()` that returns a bool (or a truthy value)

    :param subcon: Construct instance
    """

    def _decode(self, obj, context, path):
        if not self._validate(obj, context, path):
            raise ValidationError("object failed validation: {}".format(obj), path=path)
        return obj

    def _validate(self, obj, context, path):
        raise NotImplementedError


class Tunnel(Subconstruct):
    r"""
    Abstract class that allows other constructs to read part of the stream as if they were reading the entire stream. See Prefixed for example.

    Needs to implement `_decode()` for parsing and `_encode()` for building.
    """

    def _parse(self, stream, context, path):
        data = stream_read_entire(stream, path)  # reads entire stream
        data = self._decode(data, context, path)
        return self.subcon.parse(data, **context)

    def _build(self, obj, stream, context, path):
        stream2 = io.BytesIO()
        buildret = self.subcon._build(obj, stream2, context, path)
        data = stream2.getvalue()
        data = self._encode(data, context, path)
        stream_write(stream, data, len(data), path)
        return obj

    def _sizeof(self, context, path):
        raise SizeofError(path=path)

    def _decode(self, data, context, path):
        raise NotImplementedError

    def _encode(self, data, context, path):
        raise NotImplementedError


class Computed(Construct):
    r"""
    Field computing a value from the context dictionary or some outer source like os.urandom or random module. Underlying byte stream is unaffected. The source can be non-deterministic.

    Parsing and Building return the value returned by the context lambda (although a constant value can also be used). Size is defined as 0 because parsing and building does not consume or produce bytes into the stream.

    :param func: context lambda or constant value

    Can propagate any exception from the lambda, possibly non-ConstructError.

    Example::
        >>> d = Struct(
        ...     "width" / Byte,
        ...     "height" / Byte,
        ...     "total" / Computed(this.width * this.height),
        ... )
        >>> d.build(dict(width=4,height=5))
        b'\x04\x05'
        >>> d.parse(b"12")
        Container(width=49, height=50, total=2450)

        >>> d = Computed(7)
        >>> d.parse(b"")
        7
        >>> d = Computed(lambda ctx: 7)
        >>> d.parse(b"")
        7

        >>> import os
        >>> d = Computed(lambda ctx: os.urandom(10))
        >>> d.parse(b"")
        b'\x98\xc2\xec\x10\x07\xf5\x8e\x98\xc2\xec'
    """

    def __init__(self, func):
        super().__init__()
        self.func = func
        self.flagbuildnone = True

    def _parse(self, stream, context, path):
        return self.func(context) if callable(self.func) else self.func

    def _build(self, obj, stream, context, path):
        return self.func(context) if callable(self.func) else self.func

    def _sizeof(self, context, path):
        return 0


class Struct(Construct):
    r"""
    Sequence of usually named constructs, similar to structs in C. The members are parsed and build in the order they are defined. If a member is anonymous (its name is None) then it gets parsed and the value discarded, or it gets build from nothing (from None).

    Some fields do not need to be named, since they are built without value anyway. See: Const Padding Check Error Pass Terminated Seek Tell for examples of such fields.

    Operator + can also be used to make Structs (although not recommended).

    Parses into a Container (dict with attribute and key access) where keys match subcon names. Builds from a dict (not necessarily a Container) where each member gets a value from the dict matching the subcon name. If field has build-from-none flag, it gets build even when there is no matching entry in the dict. Size is the sum of all subcon sizes, unless any subcon raises SizeofError.

    This class does context nesting, meaning its members are given access to a new dictionary where the "_" entry points to the outer context. When parsing, each member gets parsed and subcon parse return value is inserted into context under matching key only if the member was named. When building, the matching entry gets inserted into context before subcon gets build, and if subcon build returns a new value (not None) that gets replaced in the context.

    This class exposes subcons as attributes. You can refer to subcons that were inlined (and therefore do not exist as variable in the namespace) by accessing the struct attributes, under same name. Also note that compiler does not support this feature. See examples.

    This class exposes subcons in the context. You can refer to subcons that were inlined (and therefore do not exist as variable in the namespace) within other inlined fields using the context. Note that you need to use a lambda (`this` expression is not supported). Also note that compiler does not support this feature. See examples.

    This class supports stopping. If :class:`~malstruct.core.StopIf` field is a member, and it evaluates its lambda as positive, this class ends parsing or building as successful without processing further fields.

    :param \*subcons: Construct instances, list of members, some can be anonymous
    :param \*\*subconskw: Construct instances, list of members (requires Python 3.6)

    :raises StreamError: requested reading negative amount, could not read enough bytes, requested writing different amount than actual data, or could not write all bytes
    :raises KeyError: building a subcon but found no corresponding key in dictionary

    Example::

        >>> d = Struct("num"/Int8ub, "data"/Bytes(this.num))
        >>> d.parse(b"\x04DATA")
        Container(num=4, data=b"DATA")
        >>> d.build(dict(num=4, data=b"DATA"))
        b"\x04DATA"

        >>> d = Struct(Const(b"MZ"), Padding(2), Pass, Terminated)
        >>> d.build({})
        b'MZ\x00\x00'
        >>> d.parse(_)
        Container()
        >>> d.sizeof()
        4

        >>> d = Struct(
        ...     "animal" / Enum(Byte, giraffe=1),
        ... )
        >>> d.animal.giraffe
        'giraffe'
        >>> d = Struct(
        ...     "count" / Byte,
        ...     "data" / Bytes(lambda this: this.count - this._subcons.count.sizeof()),
        ... )
        >>> d.build(dict(count=3, data=b"12"))
        b'\x0312'

        Alternative syntax (not recommended):
        >>> ("a"/Byte + "b"/Byte + "c"/Byte + "d"/Byte)

        Alternative syntax, but requires Python 3.6 or any PyPy:
        >>> Struct(a=Byte, b=Byte, c=Byte, d=Byte)
    """

    def __init__(self, *subcons, **subconskw):
        super().__init__()
        self.subcons = list(subcons) + list(k / v for k, v in subconskw.items())
        self._subcons = Container((sc.name, sc) for sc in self.subcons if sc.name)
        self.flagbuildnone = all(sc.flagbuildnone for sc in self.subcons)

    def __getattr__(self, name):
        if name in self._subcons:
            return self._subcons[name]
        raise AttributeError

    def _parse(self, stream, context, path):
        obj = Container()
        obj._io = stream
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
        for sc in self.subcons:
            try:
                subobj = sc._parsereport(stream, context, path)
                if sc.name:
                    obj[sc.name] = subobj
                    context[sc.name] = subobj
            except StopFieldError:
                break
        return obj

    def _build(self, obj, stream, context, path):
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


class Sequence(Construct):
    r"""
    Sequence of usually un-named constructs. The members are parsed and build in the order they are defined. If a member is named, its parsed value gets inserted into the context. This allows using members that refer to previous members.

    Operator >> can also be used to make Sequences (although not recommended).

    Parses into a ListContainer (list with pretty-printing) where values are in same order as subcons. Builds from a list (not necessarily a ListContainer) where each subcon is given the element at respective position. Size is the sum of all subcon sizes, unless any subcon raises SizeofError.

    This class does context nesting, meaning its members are given access to a new dictionary where the "_" entry points to the outer context. When parsing, each member gets parsed and subcon parse return value is inserted into context under matching key only if the member was named. When building, the matching entry gets inserted into context before subcon gets build, and if subcon build returns a new value (not None) that gets replaced in the context.

    This class exposes subcons as attributes. You can refer to subcons that were inlined (and therefore do not exist as variable in the namespace) by accessing the struct attributes, under same name. Also note that compiler does not support this feature. See examples.

    This class exposes subcons in the context. You can refer to subcons that were inlined (and therefore do not exist as variable in the namespace) within other inlined fields using the context. Note that you need to use a lambda (`this` expression is not supported). Also note that compiler does not support this feature. See examples.

    This class supports stopping. If :class:`~malstruct.core.StopIf` field is a member, and it evaluates its lambda as positive, this class ends parsing or building as successful without processing further fields.

    :param \*subcons: Construct instances, list of members, some can be named
    :param \*\*subconskw: Construct instances, list of members (requires Python 3.6)

    :raises StreamError: requested reading negative amount, could not read enough bytes, requested writing different amount than actual data, or could not write all bytes
    :raises KeyError: building a subcon but found no corresponding key in dictionary

    Example::

        >>> d = Sequence(Byte, Float32b)
        >>> d.build([0, 1.23])
        b'\x00?\x9dp\xa4'
        >>> d.parse(_)
        [0, 1.2300000190734863] # a ListContainer

        >>> d = Sequence(
        ...     "animal" / Enum(Byte, giraffe=1),
        ... )
        >>> d.animal.giraffe
        'giraffe'
        >>> d = Sequence(
        ...     "count" / Byte,
        ...     "data" / Bytes(lambda this: this.count - this._subcons.count.sizeof()),
        ... )
        >>> d.build([3, b"12"])
        b'\x0312'

        Alternative syntax (not recommended):
        >>> (Byte >> Byte >> "c"/Byte >> "d"/Byte)

        Alternative syntax, but requires Python 3.6 or any PyPy:
        >>> Sequence(a=Byte, b=Byte, c=Byte, d=Byte)
    """

    def __init__(self, *subcons, **subconskw):
        super().__init__()
        self.subcons = list(subcons) + list(k / v for k, v in subconskw.items())
        self._subcons = Container((sc.name, sc) for sc in self.subcons if sc.name)
        self.flagbuildnone = all(sc.flagbuildnone for sc in self.subcons)

    def __getattr__(self, name):
        if name in self._subcons:
            return self._subcons[name]
        raise AttributeError

    def _parse(self, stream, context, path):
        obj = ListContainer()
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
        for sc in self.subcons:
            try:
                subobj = sc._parsereport(stream, context, path)
                obj.append(subobj)
                if sc.name:
                    context[sc.name] = subobj
            except StopFieldError:
                break
        return obj

    def _build(self, obj, stream, context, path):
        if obj is None:
            obj = ListContainer([None for sc in self.subcons])
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
        objiter = iter(obj)
        retlist = ListContainer()
        for i, sc in enumerate(self.subcons):
            try:
                subobj = next(objiter)
                if sc.name:
                    context[sc.name] = subobj

                buildret = sc._build(subobj, stream, context, path)
                retlist.append(buildret)

                if sc.name:
                    context[sc.name] = buildret
            except StopFieldError:
                break
        return retlist

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


class Array(Subconstruct):
    r"""
    Homogenous array of elements, similar to C# generic T[].

    Parses into a ListContainer (a list). Parsing and building processes an exact amount of elements. If given list has more or less than count elements, raises RangeError. Size is defined as count multiplied by subcon size, but only if subcon is fixed size.

    Operator [] can be used to make Array instances (recommended syntax).

    :param count: integer or context lambda, strict amount of elements
    :param subcon: Construct instance, subcon to process individual elements
    :param discard: optional, bool, if set then parsing returns empty list

    :raises StreamError: requested reading negative amount, could not read enough bytes, requested writing different amount than actual data, or could not write all bytes
    :raises RangeError: specified count is not valid
    :raises RangeError: given object has different length than specified count

    Can propagate any exception from the lambdas, possibly non-ConstructError.

    Example::

        >>> d = Array(5, Byte) or Byte[5]
        >>> d.build(range(5))
        b'\x00\x01\x02\x03\x04'
        >>> d.parse(_)
        [0, 1, 2, 3, 4]
    """

    def __init__(self, count, subcon, discard=False):
        super().__init__(subcon)
        self.count = count
        self.discard = discard

    def _parse(self, stream, context, path):
        count = evaluate(self.count, context)
        if not 0 <= count:
            raise RangeError("invalid count {}".format(count), path=path)
        discard = self.discard
        obj = ListContainer()
        for i in range(count):
            context._index = i
            e = self.subcon._parsereport(stream, context, path)
            if not discard:
                obj.append(e)
        return obj

    def _build(self, obj, stream, context, path):
        count = evaluate(self.count, context)
        if not 0 <= count:
            raise RangeError("invalid count {}".format(count), path=path)
        if not len(obj) == count:
            raise RangeError(
                "expected %d elements, found %d" % (count, len(obj)), path=path
            )
        discard = self.discard
        retlist = ListContainer()
        for i, e in enumerate(obj):
            context._index = i
            buildret = self.subcon._build(e, stream, context, path)
            if not discard:
                retlist.append(buildret)
        return retlist

    def _sizeof(self, context, path):
        try:
            count = evaluate(self.count, context)
        except (KeyError, AttributeError):
            raise SizeofError(
                "cannot calculate size, key not found in context", path=path
            )
        size = 0
        for i in range(count):
            context._index = i
            size += self.subcon._sizeof(context, path)
        return size


class Range(Subconstruct):
    r"""
    A homogenous array of elements. The array will iterate through between ``min`` to ``max`` times. If an exception occurs (EOF, validation error), the repeater exits cleanly. If less than ``min`` units have been successfully parsed, a RangeError is raised.

    .. seealso:: Analog :func:`~construct.core.GreedyRange` that parses until end of stream.

    .. note:: This object requires a seekable stream for parsing.

    :param min: the minimal count
    :param max: the maximal count
    :param subcon: the subcon to process individual elements

    Example::

        >>> Range(3, 5, Byte).build([1,2,3,4])
        '\x01\x02\x03\x04'
        >>> Range(3, 5, Byte).parse(_)
        ListContainer([1, 2, 3, 4])

        >>> Range(3, 5, Byte).build([1,2])
        Traceback (most recent call last):
            ...
        RangeError: expected from 3 to 5 elements, found 2
        >>> Range(3, 5, Byte).build([1,2,3,4,5,6])
        Traceback (most recent call last):
            ...
        RangeError: expected from 3 to 5 elements, found 6
    """

    __slots__ = ["min", "max"]

    def __init__(self, min, max, subcon):
        super().__init__(subcon)
        self.min = min
        self.max = max

    def _parse(self, stream, context, path):
        min_ = evaluate(self.min, context)
        max_ = evaluate(self.max, context)
        if not 0 <= min_ <= max_ <= sys.maxsize:
            raise RangeError(f"[{path}] unsane min {min_} and max {max_}")
        obj = ListContainer()
        try:
            i = 0
            while len(obj) < max_:
                context._index = i
                fallback = stream.tell()
                obj.append(self.subcon._parsereport(stream, context, path))
                if stream.tell() == fallback:
                    raise ExplicitError(f"[{path}] Infinite loop detected.")
                i += 1
        except StopIteration:
            pass
        except ExplicitError:
            raise
        except Exception:  # TODO: catch ConstructError instead?
            if len(obj) < min_:
                raise RangeError(
                    f"[{path}] expected {min_} to {max_}, found {len(obj)}"
                )
            stream.seek(fallback)
        return obj

    def _build(self, obj, stream, context, path):
        min_ = evaluate(self.min, context)
        max_ = evaluate(self.max, context)
        if not 0 <= min_ <= max_ <= sys.maxsize:
            raise RangeError(f"[{path}] unsane min {min_} and max {max_}")
        if not isinstance(obj, collections.abc.Sequence):
            raise RangeError(f"[{path}] expected sequence type, found {type(obj)}")
        if not min_ <= len(obj) <= max_:
            raise RangeError(
                f"[{path}] expected from {min_} to {max_} elements, found {len(obj)}"
            )
        retlist = ListContainer()
        try:
            for i, subobj in enumerate(obj):
                context._index = i
                buildret = self.subcon._build(subobj, stream, context, path)
                retlist.append(buildret)
        except StopIteration:
            pass
        except ExplicitError:
            raise
        except Exception:
            if len(obj) < min_:
                raise RangeError(
                    f"[{path}] expected {min_} to {max_}, found {len(obj)}"
                )
            else:
                raise
        return retlist

    def _sizeof(self, context, path):
        # WARNING: possibly broken by StopIf
        try:
            min_ = evaluate(self.min, context)
            max_ = evaluate(self.max, context)
        except (KeyError, AttributeError):
            raise SizeofError("cannot calculate size, key not found in context")
        if min_ == max_:
            size = 0
            for i in range(min_):
                context._index = i
                size += self.subcon._sizeof(context, path)
            return size
        else:
            raise SizeofError("cannot calculate size")


class GreedyRange(Subconstruct):
    r"""
    Homogenous array of elements, similar to C# generic IEnumerable<T>, but works with unknown count of elements by parsing until end of stream.

    Parses into a ListContainer (a list). Parsing stops when an exception occured when parsing the subcon, either due to EOF or subcon format not being able to parse the data. Either way, when GreedyRange encounters either failure it seeks the stream back to a position after last successful subcon parsing. Builds from enumerable, each element as-is. Size is undefined.

    This class supports stopping. If :class:`~malstruct.core.StopIf` field is a member, and it evaluates its lambda as positive, this class ends parsing or building as successful without processing further fields.

    :param subcon: Construct instance, subcon to process individual elements
    :param discard: optional, bool, if set then parsing returns empty list

    :raises StreamError: requested reading negative amount, could not read enough bytes, requested writing different amount than actual data, or could not write all bytes
    :raises StreamError: stream is not seekable and tellable

    Can propagate any exception from the lambdas, possibly non-ConstructError.

    Example::

        >>> d = GreedyRange(Byte)
        >>> d.build(range(8))
        b'\x00\x01\x02\x03\x04\x05\x06\x07'
        >>> d.parse(_)
        [0, 1, 2, 3, 4, 5, 6, 7]
    """

    def __init__(self, subcon, discard=False):
        super().__init__(subcon)
        self.discard = discard

    def _parse(self, stream, context, path):
        discard = self.discard
        obj = ListContainer()
        try:
            for i in itertools.count():
                context._index = i
                fallback = stream_tell(stream, path)
                e = self.subcon._parsereport(stream, context, path)
                if not discard:
                    obj.append(e)
        except StopFieldError:
            pass
        except ExplicitError:
            raise
        except Exception:
            stream_seek(stream, fallback, 0, path)
        return obj

    def _build(self, obj, stream, context, path):
        discard = self.discard
        try:
            retlist = ListContainer()
            for i, e in enumerate(obj):
                context._index = i
                buildret = self.subcon._build(e, stream, context, path)
                if not discard:
                    retlist.append(buildret)
            return retlist
        except StopFieldError:
            pass

    def _sizeof(self, context, path):
        raise SizeofError(path=path)


class RepeatUntil(Subconstruct):
    r"""
    Homogenous array of elements, similar to C# generic IEnumerable<T>, that repeats until the predicate indicates it to stop. Note that the last element (that predicate indicated as True) is included in the return list.

    Parse iterates indefinately until last element passed the predicate. Build iterates indefinately over given list, until an element passed the precicate (or raises RepeatError if no element passed it). Size is undefined.

    :param predicate: lambda that takes (obj, list, context) and returns True to break or False to continue (or a truthy value)
    :param subcon: Construct instance, subcon used to parse and build each element
    :param discard: optional, bool, if set then parsing returns empty list

    :raises StreamError: requested reading negative amount, could not read enough bytes, requested writing different amount than actual data, or could not write all bytes
    :raises RepeatError: consumed all elements in the stream but neither passed the predicate

    Can propagate any exception from the lambda, possibly non-ConstructError.

    Example::

        >>> d = RepeatUntil(lambda x,lst,ctx: x > 7, Byte)
        >>> d.build(range(20))
        b'\x00\x01\x02\x03\x04\x05\x06\x07\x08'
        >>> d.parse(b"\x01\xff\x02")
        [1, 255]

        >>> d = RepeatUntil(lambda x,lst,ctx: lst[-2:] == [0,0], Byte)
        >>> d.parse(b"\x01\x00\x00\xff")
        [1, 0, 0]
    """

    def __init__(self, predicate, subcon, discard=False):
        super().__init__(subcon)
        self.predicate = predicate
        self.discard = discard

    def _parse(self, stream, context, path):
        predicate = self.predicate
        discard = self.discard
        if not callable(predicate):
            predicate = lambda _1, _2, _3: predicate
        obj = ListContainer()
        for i in itertools.count():
            context._index = i
            e = self.subcon._parsereport(stream, context, path)
            if not discard:
                obj.append(e)
            if predicate(e, obj, context):
                return obj

    def _build(self, obj, stream, context, path):
        predicate = self.predicate
        discard = self.discard
        if not callable(predicate):
            predicate = lambda _1, _2, _3: predicate
        partiallist = ListContainer()
        retlist = ListContainer()
        for i, e in enumerate(obj):
            context._index = i
            buildret = self.subcon._build(e, stream, context, path)
            if not discard:
                retlist.append(buildret)
                partiallist.append(buildret)
            if predicate(e, partiallist, context):
                break
        else:
            raise RepeatError(
                "expected any item to match predicate, when building", path=path
            )
        return retlist

    def _sizeof(self, context, path):
        raise SizeofError(
            "cannot calculate size, amount depends on actual data", path=path
        )


class Renamed(Subconstruct):
    r"""
    Special wrapper that allows a Struct (or other similar class) to see a field as having a name (or a different name) or having a parsed hook. Library classes do not have names (its None). Renamed does not change a field, only wraps it like a candy with a label. Used internally by / and * operators.

    Also this wrapper is responsible for building a path info (a chain of names) that gets attached to error message when parsing, building, or sizeof fails. Fields that are not named do not appear in the path string.

    Parsing building and size are deferred to subcon.

    :param subcon: Construct instance
    :param newname: optional, string
    :param newdocs: optional, string
    :param newparsed: optional, lambda

    Example::

        >>> "number" / Int32ub
        <Renamed: number>
    """

    def __init__(self, subcon, newname=None, newdocs=None, newparsed=None):
        super().__init__(subcon)
        self.name = newname if newname else subcon.name
        self.docs = newdocs if newdocs else subcon.docs
        self.parsed = newparsed if newparsed else subcon.parsed

    def __getattr__(self, name):
        return getattr(self.subcon, name)

    def _parse(self, stream, context, path):
        path += " -> {}".format(self.name)
        return self.subcon._parsereport(stream, context, path)

    def _build(self, obj, stream, context, path):
        path += " -> {}".format(self.name)
        return self.subcon._build(obj, stream, context, path)

    def _sizeof(self, context, path):
        path += " -> {}".format(self.name)
        return self.subcon._sizeof(context, path)
