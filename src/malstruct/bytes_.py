"""
Bytes and bits
"""

from malstruct.lib import integer2bytes

from .core import Construct
from .exceptions import *
from .helpers import singleton, stream_read, stream_read_entire, stream_write


class Bytes(Construct):
    r"""
    Field consisting of a specified number of bytes.

    Parses into a bytes (of given length). Builds into the stream directly (but checks that given object matches specified length). Can also build from an integer for convenience (although BytesInteger should be used instead). Size is the specified length.

    Can also build from a bytearray.

    :param length: integer or context lambda

    :raises StreamError: requested reading negative amount, could not read enough bytes, requested writing different amount than actual data, or could not write all bytes
    :raises StringError: building from non-bytes value, perhaps unicode

    Can propagate any exception from the lambda, possibly non-ConstructError.

    Example::

        >>> d = Bytes(4)
        >>> d.parse(b'beef')
        b'beef'
        >>> d.build(b'beef')
        b'beef'
        >>> d.build(0)
        b'\x00\x00\x00\x00'
        >>> d.sizeof()
        4

        >>> d = Struct(
        ...     "length" / Int8ub,
        ...     "data" / Bytes(this.length),
        ... )
        >>> d.parse(b"\x04beef")
        Container(length=4, data=b'beef')
        >>> d.sizeof()
        malstruct.core.SizeofError: cannot calculate size, key not found in context
    """

    def __init__(self, length):
        super().__init__()
        self.length = length

    def _parse(self, stream, context, path):
        length = self.length(context) if callable(self.length) else self.length
        return stream_read(stream, length, path)

    def _build(self, obj, stream, context, path):
        length = self.length(context) if callable(self.length) else self.length
        data = integer2bytes(obj, length) if isinstance(obj, int) else obj
        data = bytes(data) if type(data) is bytearray else data
        stream_write(stream, data, length, path)
        return data

    def _sizeof(self, context, path):
        try:
            return self.length(context) if callable(self.length) else self.length
        except (KeyError, AttributeError):
            raise SizeofError(
                "cannot calculate size, key not found in context", path=path
            )


@singleton
class GreedyBytes(Construct):
    r"""
    Field consisting of unknown number of bytes.

    Parses the stream to the end. Builds into the stream directly (without checks). Size is undefined.

    Can also build from a bytearray.

    :raises StreamError: stream failed when reading until EOF
    :raises StringError: building from non-bytes value, perhaps unicode

    Example::

        >>> GreedyBytes.parse(b"asislight")
        b'asislight'
        >>> GreedyBytes.build(b"asislight")
        b'asislight'
    """

    def _parse(self, stream, context, path):
        return stream_read_entire(stream, path)

    def _build(self, obj, stream, context, path):
        data = bytes(obj) if type(obj) is bytearray else obj
        stream_write(stream, data, len(data), path)
        return data
