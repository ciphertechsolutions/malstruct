import io

from .core import Construct, Subconstruct, evaluate
from .exceptions import *
from .helpers import (
    BytesIOWithOffsets,
    singleton,
    stream_read,
    stream_seek,
    stream_tell,
)


class Pointer(Subconstruct):
    r"""
    Jumps in the stream forth and back for one field.

    Parsing and building seeks the stream to new location, processes subcon, and seeks back to original location. Size is defined as 0 but that does not mean no bytes are written into the stream.

    Offset can be positive, indicating a position from stream beginning forward, or negative, indicating a position from EOF backwards. Alternatively the offset can be interpreted as relative to the current stream position.

    :param offset: integer or context lambda, positive or negative
    :param subcon: Construct instance
    :param stream: None to use original stream (default), or context lambda to provide a different stream
    :param relativeOffset: True to interpret the offset as relative to the current stream position

    :raises StreamError: requested reading negative amount, could not read enough bytes, requested writing different amount than actual data, or could not write all bytes
    :raises StreamError: stream is not seekable and tellable

    Can propagate any exception from the lambda, possibly non-ConstructError.

    Example::

        >>> d = Pointer(8, Bytes(1))
        >>> d.parse(b"abcdefghijkl")
        b'i'
        >>> d.build(b"Z")
        b'\x00\x00\x00\x00\x00\x00\x00\x00Z'
    """

    def __init__(self, offset, subcon, stream=None, relativeOffset=False):
        super().__init__(subcon)
        self.offset = offset
        self.stream = stream
        self.relativeOffset = relativeOffset

    def _pointer_seek(self, stream, context, path):
        offset = evaluate(self.offset, context)
        stream = evaluate(self.stream, context) or stream
        fallback = stream_tell(stream, path)
        if self.relativeOffset:
            stream_seek(stream, offset, 1, path)
        else:
            stream_seek(stream, offset, 2 if offset < 0 else 0, path)

        return fallback

    def _parse(self, stream, context, path):
        fallback = self._pointer_seek(stream, context, path)
        obj = self.subcon._parsereport(stream, context, path)
        stream_seek(stream, fallback, 0, path)
        return obj

    def _build(self, obj, stream, context, path):
        fallback = self._pointer_seek(stream, context, path)
        buildret = self.subcon._build(obj, stream, context, path)
        stream_seek(stream, fallback, 0, path)
        return buildret

    def _sizeof(self, context, path):
        return 0


class Peek(Subconstruct):
    r"""
    Peeks at the stream.

    Parsing sub-parses (and returns None if failed), then reverts stream to original position. Building does nothing (its NOT deferred). Size is defined as 0 because there is no building.

    This class is used in :class:`~malstruct.core.Union` class to parse each member.

    :param subcon: Construct instance

    :raises StreamError: requested reading negative amount, could not read enough bytes, requested writing different amount than actual data, or could not write all bytes
    :raises StreamError: stream is not seekable and tellable

    Example::

        >>> d = Sequence(Peek(Int8ub), Peek(Int16ub))
        >>> d.parse(b"\x01\x02")
        [1, 258]
        >>> d.sizeof()
        0
    """

    def __init__(self, subcon):
        super().__init__(subcon)
        self.flagbuildnone = True

    def _parse(self, stream, context, path):
        fallback = stream_tell(stream, path)
        try:
            return self.subcon._parsereport(stream, context, path)
        except ExplicitError:
            raise
        except ConstructError:
            pass
        finally:
            stream_seek(stream, fallback, 0, path)

    def _build(self, obj, stream, context, path):
        return obj

    def _sizeof(self, context, path):
        return 0


class OffsettedEnd(Subconstruct):
    r"""
    Parses all bytes in the stream till `EOF plus a negative endoffset` is reached.

    This is useful when GreedyBytes (or any other greedy construct) is followed by a fixed-size footer.

    Parsing determines the length of the stream and reads all bytes till EOF plus `endoffset` is reached, then defers to subcon using new BytesIO with said bytes. Building defers to subcon as-is. Size is undefined.

    :param endoffset: integer or context lambda, only negative offsets or zero are allowed
    :param subcon: Construct instance
    :param absolute: Seek relative to the start of the stream rather than relative to the last occurence of a subconstruct

    :raises StreamError: could not read enough bytes
    :raises StreamError: reads behind the stream (if endoffset is positive)

    Example::

        >>> d = Struct(
        ...     "header" / Bytes(2),
        ...     "data" / OffsettedEnd(-2, GreedyBytes),
        ...     "footer" / Bytes(2),
        ... )
        >>> d.parse(b"\x01\x02\x03\x04\x05\x06\x07")
        Container(header=b'\x01\x02', data=b'\x03\x04\x05', footer=b'\x06\x07')
    """

    def __init__(self, endoffset, subcon, absolute=False):
        super().__init__(subcon)
        self.endoffset = endoffset
        self.absolute = absolute

    def _parse(self, stream, context, path):
        endoffset = evaluate(self.endoffset, context)
        curpos = stream_tell(stream, path)
        stream_seek(stream, 0, 2, path)
        endpos = stream_tell(stream, path)
        stream_seek(stream, curpos, 0, path)
        length = endpos + endoffset - curpos
        substream = (
            BytesIOWithOffsets.from_reading(stream, length, path)
            if self.absolute
            else io.BytesIO(stream_read(stream, length, path))
        )
        return self.subcon._parsereport(substream, context, path)

    def _build(self, obj, stream, context, path):
        return self.subcon._build(obj, stream, context, path)

    def _sizeof(self, context, path):
        raise SizeofError(path=path)


class Seek(Construct):
    r"""
    Seeks the stream.

    Parsing and building seek the stream to given location (and whence), and return stream.seek() return value. Size is not defined.

    .. seealso:: Analog :class:`~malstruct.core.Pointer` wrapper that has same side effect but also processes a subcon, and also seeks back.

    :param at: integer or context lambda, where to jump to
    :param whence: optional, integer or context lambda, is the offset from beginning (0) or from current position (1) or from EOF (2), default is 0

    :raises StreamError: stream is not seekable

    Can propagate any exception from the lambda, possibly non-ConstructError.

    Example::

        >>> d = (Seek(5) >> Byte)
        >>> d.parse(b"01234x")
        [5, 120]

        >>> d = (Bytes(10) >> Seek(5) >> Byte)
        >>> d.build([b"0123456789", None, 255])
        b'01234\xff6789'
    """

    def __init__(self, at, whence=0):
        super().__init__()
        self.at = at
        self.whence = whence
        self.flagbuildnone = True

    def _parse(self, stream, context, path):
        at = evaluate(self.at, context)
        whence = evaluate(self.whence, context)
        return stream_seek(stream, at, whence, path)

    def _build(self, obj, stream, context, path):
        at = evaluate(self.at, context)
        whence = evaluate(self.whence, context)
        return stream_seek(stream, at, whence, path)

    def _sizeof(self, context, path):
        raise SizeofError(
            "Seek only moves the stream, size is not meaningful", path=path
        )


@singleton
class Tell(Construct):
    r"""
    Tells the stream.

    Parsing and building return current stream offset using using stream.tell(). Size is defined as 0 because parsing and building does not consume or add into the stream.

    Tell is useful for adjusting relative offsets to absolute positions, or to measure sizes of Constructs. To get an absolute pointer, use a Tell plus a relative offset. To get a size, place two Tells and measure their difference using a Compute field. However, its recommended to use :class:`~malstruct.core.RawCopy` instead of manually extracting two positions and computing difference.

    :raises StreamError: stream is not tellable

    Example::

        >>> d = Struct("num"/VarInt, "offset"/Tell)
        >>> d.parse(b"X")
        Container(num=88, offset=1)
        >>> d.build(dict(num=88))
        b'X'
    """

    def __init__(self):
        super().__init__()
        self.flagbuildnone = True

    def _parse(self, stream, context, path):
        return stream_tell(stream, path)

    def _build(self, obj, stream, context, path):
        return stream_tell(stream, path)

    def _sizeof(self, context, path):
        return 0


@singleton
class Terminated(Construct):
    r"""
    Asserts end of stream (EOF). You can use it to ensure no more unparsed data follows in the stream.

    Parsing checks if stream reached EOF, and raises TerminatedError if not. Building does nothing. Size is defined as 0 because parsing and building does not consume or add into the stream, as far as other constructs see it.

    :raises TerminatedError: stream not at EOF when parsing

    Example::

        >>> Terminated.parse(b"")
        None
        >>> Terminated.parse(b"remaining")
        malstruct.core.TerminatedError: expected end of stream
    """

    def __init__(self):
        super().__init__()
        self.flagbuildnone = True

    def _parse(self, stream, context, path):
        if stream.read(1):
            raise TerminatedError("expected end of stream", path=path)

    def _build(self, obj, stream, context, path):
        return obj

    def _sizeof(self, context, path):
        raise SizeofError(path=path)
