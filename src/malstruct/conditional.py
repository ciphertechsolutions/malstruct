"""
Conditional constructs
"""

from malstruct.lib import Container

from .alignment import Pass
from .bytes_ import Bytes
from .core import Construct, GreedyRange, Sequence, Struct, evaluate
from .exceptions import *
from .helpers import stream_seek, stream_tell, stream_write


class Union(Construct):
    r"""
    Treats the same data as multiple constructs (similar to C union) so you can look at the data in multiple views. Fields are usually named (so parsed values are inserted into dictionary under same name).

    Parses subcons in sequence, and reverts the stream back to original position after each subcon. Afterwards, advances the stream by selected subcon. Builds from first subcon that has a matching key in given dict. Size is undefined (because parsefrom is not used for building).

    This class does context nesting, meaning its members are given access to a new dictionary where the "_" entry points to the outer context. When parsing, each member gets parsed and subcon parse return value is inserted into context under matching key only if the member was named. When building, the matching entry gets inserted into context before subcon gets build, and if subcon build returns a new value (not None) that gets replaced in the context.

    This class exposes subcons as attributes. You can refer to subcons that were inlined (and therefore do not exist as variable in the namespace) by accessing the struct attributes, under same name. Also note that compiler does not support this feature. See examples.

    This class exposes subcons in the context. You can refer to subcons that were inlined (and therefore do not exist as variable in the namespace) within other inlined fields using the context. Note that you need to use a lambda (`this` expression is not supported). Also note that compiler does not support this feature. See examples.

    .. warning:: If you skip `parsefrom` parameter then stream will be left back at starting offset, not seeked to any common denominator.

    :param parsefrom: how to leave stream after parsing, can be integer index or string name selecting a subcon, or None (leaves stream at initial offset, the default), or context lambda
    :param \*subcons: Construct instances, list of members, some can be anonymous
    :param \*\*subconskw: Construct instances, list of members (requires Python 3.6)

    :raises StreamError: requested reading negative amount, could not read enough bytes, requested writing different amount than actual data, or could not write all bytes
    :raises StreamError: stream is not seekable and tellable
    :raises UnionError: selector does not match any subcon, or dict given to build does not contain any keys matching any subcon
    :raises IndexError: selector does not match any subcon
    :raises KeyError: selector does not match any subcon

    Can propagate any exception from the lambda, possibly non-ConstructError.

    Example::

        >>> d = Union(0,
        ...     "raw" / Bytes(8),
        ...     "ints" / Int32ub[2],
        ...     "shorts" / Int16ub[4],
        ...     "chars" / Byte[8],
        ... )
        >>> d.parse(b"12345678")
        Container(raw=b'12345678', ints=[825373492, 892745528], shorts=[12594, 13108, 13622, 14136], chars=[49, 50, 51, 52, 53, 54, 55, 56])
        >>> d.build(dict(chars=range(8)))
        b'\x00\x01\x02\x03\x04\x05\x06\x07'

        >>> d = Union(None,
        ...     "animal" / Enum(Byte, giraffe=1),
        ... )
        >>> d.animal.giraffe
        'giraffe'
        >>> d = Union(None,
        ...     "chars" / Byte[4],
        ...     "data" / Bytes(lambda this: this._subcons.chars.sizeof()),
        ... )
        >>> d.parse(b"\x01\x02\x03\x04")
        Container(chars=[1, 2, 3, 4], data=b'\x01\x02\x03\x04')

        Alternative syntax, but requires Python 3.6 or any PyPy:
        >>> Union(0, raw=Bytes(8), ints=Int32ub[2], shorts=Int16ub[4], chars=Byte[8])
    """

    def __init__(self, parsefrom=None, *subcons, **subconskw):
        if isinstance(parsefrom, Construct):
            raise UnionError(
                "parsefrom should be either: None int str context-function"
            )
        super().__init__()
        self.parsefrom = parsefrom
        self.subcons = list(subcons) + list(k / v for k, v in subconskw.items())
        self._subcons = Container((sc.name, sc) for sc in self.subcons if sc.name)

    def __getattr__(self, name):
        if name in self._subcons:
            return self._subcons[name]
        raise AttributeError

    def _parse(self, stream, context, path):
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
        fallback = stream_tell(stream, path)
        forwards = {}
        for i, sc in enumerate(self.subcons):
            subobj = sc._parsereport(stream, context, path)
            if sc.name:
                obj[sc.name] = subobj
                context[sc.name] = subobj
            forwards[i] = stream_tell(stream, path)
            if sc.name:
                forwards[sc.name] = stream_tell(stream, path)
            stream_seek(stream, fallback, 0, path)
        parsefrom = evaluate(self.parsefrom, context)
        if parsefrom is not None:
            stream_seek(stream, forwards[parsefrom], 0, path)  # raises KeyError
        return obj

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
        context.update(obj)
        for sc in self.subcons:
            if sc.flagbuildnone:
                subobj = obj.get(sc.name, None)
            elif sc.name in obj:
                subobj = obj[sc.name]
            else:
                continue

            if sc.name:
                context[sc.name] = subobj

            buildret = sc._build(subobj, stream, context, path)
            if sc.name:
                context[sc.name] = buildret
            return Container({sc.name: buildret})
        else:
            raise UnionError(
                "cannot build, none of subcons were found in the dictionary {!r}".format(
                    obj
                ),
                path=path,
            )

    def _sizeof(self, context, path):
        raise SizeofError(
            "Union builds depending on actual object dict, size is unknown", path=path
        )


class Select(Construct):
    r"""
    Selects the first matching subconstruct.

    Parses and builds by literally trying each subcon in sequence until one of them parses or builds without exception. Stream gets reverted back to original position after each failed attempt, but not if parsing succeeds. Size is not defined.

    :param \*subcons: Construct instances, list of members, some can be anonymous
    :param \*\*subconskw: Construct instances, list of members (requires Python 3.6)

    :raises StreamError: requested reading negative amount, could not read enough bytes, requested writing different amount than actual data, or could not write all bytes
    :raises StreamError: stream is not seekable and tellable
    :raises SelectError: neither subcon succeded when parsing or building

    Example::

        >>> d = Select(Int32ub, CString("utf8"))
        >>> d.build(1)
        b'\x00\x00\x00\x01'
        >>> d.build(u"Афон")
        b'\xd0\x90\xd1\x84\xd0\xbe\xd0\xbd\x00'

        Alternative syntax, but requires Python 3.6 or any PyPy:
        >>> Select(num=Int32ub, text=CString("utf8"))
    """

    def __init__(self, *subcons, **subconskw):
        super().__init__()
        self.subcons = list(subcons) + list(k / v for k, v in subconskw.items())
        self.flagbuildnone = any(sc.flagbuildnone for sc in self.subcons)

    def _parse(self, stream, context, path):
        for sc in self.subcons:
            fallback = stream_tell(stream, path)
            try:
                obj = sc._parsereport(stream, context, path)
            except ExplicitError:
                raise
            except Exception:
                stream_seek(stream, fallback, 0, path)
            else:
                return obj
        raise SelectError("no subconstruct matched", path=path)

    def _build(self, obj, stream, context, path):
        for sc in self.subcons:
            try:
                data = sc.build(obj, **context)
            except ExplicitError:
                raise
            except Exception:
                pass
            else:
                stream_write(stream, data, len(data), path)
                return obj
        raise SelectError("no subconstruct matched: {}".format(obj), path=path)


def Optional(subcon):
    r"""
    Makes an optional field.

    Parsing attempts to parse subcon. If sub-parsing fails, returns None and reports success. Building attempts to build subcon. If sub-building fails, writes nothing and reports success. Size is undefined, because whether bytes would be consumed or produced depends on actual data and actual context.

    :param subcon: Construct instance

    Example::

        Optional  <-->  Select(subcon, Pass)

        >>> d = Optional(Int64ul)
        >>> d.parse(b"12345678")
        4050765991979987505
        >>> d.parse(b"")
        None
        >>> d.build(1)
        b'\x01\x00\x00\x00\x00\x00\x00\x00'
        >>> d.build(None)
        b''
    """
    return Select(subcon, Pass)


def If(condfunc, subcon):
    r"""
    If-then conditional construct.

    Parsing evaluates condition, if True then subcon is parsed, otherwise just returns None. Building also evaluates condition, if True then subcon gets build from, otherwise does nothing. Size is either same as subcon or 0, depending how condfunc evaluates.

    :param condfunc: bool or context lambda (or a truthy value)
    :param subcon: Construct instance, used if condition indicates True

    :raises StreamError: requested reading negative amount, could not read enough bytes, requested writing different amount than actual data, or could not write all bytes

    Can propagate any exception from the lambda, possibly non-ConstructError.

    Example::

        If <--> IfThenElse(condfunc, subcon, Pass)

        >>> d = If(this.x > 0, Byte)
        >>> d.build(255, x=1)
        b'\xff'
        >>> d.build(255, x=0)
        b''
    """
    return IfThenElse(condfunc, subcon, Pass)


class IfThenElse(Construct):
    r"""
    If-then-else conditional construct, similar to ternary operator.

    Parsing and building evaluates condition, and defers to either subcon depending on the value. Size is computed the same way.

    :param condfunc: bool or context lambda (or a truthy value)
    :param thensubcon: Construct instance, used if condition indicates True
    :param elsesubcon: Construct instance, used if condition indicates False

    :raises StreamError: requested reading negative amount, could not read enough bytes, requested writing different amount than actual data, or could not write all bytes

    Can propagate any exception from the lambda, possibly non-ConstructError.

    Example::

        >>> d = IfThenElse(this.x > 0, VarInt, Byte)
        >>> d.build(255, dict(x=1))
        b'\xff\x01'
        >>> d.build(255, dict(x=0))
        b'\xff'
    """

    def __init__(self, condfunc, thensubcon, elsesubcon):
        super().__init__()
        self.condfunc = condfunc
        self.thensubcon = thensubcon
        self.elsesubcon = elsesubcon
        self.flagbuildnone = thensubcon.flagbuildnone and elsesubcon.flagbuildnone

    def _parse(self, stream, context, path):
        condfunc = evaluate(self.condfunc, context)
        sc = self.thensubcon if condfunc else self.elsesubcon
        return sc._parsereport(stream, context, path)

    def _build(self, obj, stream, context, path):
        condfunc = evaluate(self.condfunc, context)
        sc = self.thensubcon if condfunc else self.elsesubcon
        return sc._build(obj, stream, context, path)

    def _sizeof(self, context, path):
        condfunc = evaluate(self.condfunc, context)
        sc = self.thensubcon if condfunc else self.elsesubcon
        return sc._sizeof(context, path)


class Switch(Construct):
    r"""
    A conditional branch.

    Parsing and building evaluate keyfunc and select a subcon based on the value and dictionary entries. Dictionary (cases) maps values into subcons. If no case matches then `default` is used (that is Pass by default). Note that `default` is a Construct instance, not a dictionary key. Size is evaluated in same way as parsing and building, by evaluating keyfunc and selecting a field accordingly.

    :param keyfunc: context lambda or constant, that matches some key in cases
    :param cases: dict mapping keys to Construct instances
    :param default: optional, Construct instance, used when keyfunc is not found in cases, Pass is default value for this parameter, Error is a possible value for this parameter

    :raises StreamError: requested reading negative amount, could not read enough bytes, requested writing different amount than actual data, or could not write all bytes

    Can propagate any exception from the lambda, possibly non-ConstructError.

    Example::

        >>> d = Switch(this.n, { 1:Int8ub, 2:Int16ub, 4:Int32ub })
        >>> d.build(5, n=1)
        b'\x05'
        >>> d.build(5, n=4)
        b'\x00\x00\x00\x05'

        >>> d = Switch(this.n, {}, default=Byte)
        >>> d.parse(b"\x01", n=255)
        1
        >>> d.build(1, n=255)
        b"\x01"
    """

    def __init__(self, keyfunc, cases, default=None):
        if default is None:
            default = Pass
        super().__init__()
        self.keyfunc = keyfunc
        self.cases = cases
        self.default = default
        allcases = list(cases.values()) + [default]
        self.flagbuildnone = all(sc.flagbuildnone for sc in allcases)

    def _parse(self, stream, context, path):
        keyfunc = evaluate(self.keyfunc, context)
        sc = self.cases.get(keyfunc, self.default)
        return sc._parsereport(stream, context, path)

    def _build(self, obj, stream, context, path):
        keyfunc = evaluate(self.keyfunc, context)
        sc = self.cases.get(keyfunc, self.default)
        return sc._build(obj, stream, context, path)

    def _sizeof(self, context, path):
        try:
            keyfunc = evaluate(self.keyfunc, context)
            sc = self.cases.get(keyfunc, self.default)
            return sc._sizeof(context, path)

        except (KeyError, AttributeError):
            raise SizeofError(
                "cannot calculate size, key not found in context", path=path
            )


class StopIf(Construct):
    r"""
    Checks for a condition, and stops certain classes (:class:`~malstruct.core.Struct` :class:`~malstruct.core.Sequence` :class:`~malstruct.core.GreedyRange`) from parsing or building further.

    Parsing and building check the condition, and raise StopFieldError if indicated. Size is undefined.

    :param condfunc: bool or context lambda (or truthy value)

    :raises StopFieldError: used internally

    Can propagate any exception from the lambda, possibly non-ConstructError.

    Example::

        >>> Struct('x'/Byte, StopIf(this.x == 0), 'y'/Byte)
        >>> Sequence('x'/Byte, StopIf(this.x == 0), 'y'/Byte)
        >>> GreedyRange(FocusedSeq(0, 'x'/Byte, StopIf(this.x == 0)))
    """

    def __init__(self, condfunc):
        super().__init__()
        self.condfunc = condfunc
        self.flagbuildnone = True

    def _parse(self, stream, context, path):
        condfunc = evaluate(self.condfunc, context)
        if condfunc:
            raise StopFieldError(path=path)

    def _build(self, obj, stream, context, path):
        condfunc = evaluate(self.condfunc, context)
        if condfunc:
            raise StopFieldError(path=path)

    def _sizeof(self, context, path):
        raise SizeofError(
            "StopIf cannot determine size because it depends on actual context which then depends on actual data and outer constructs",
            path=path,
        )
