import io
import os

from .exceptions import *


def singleton(arg):
    x = arg()
    return x


def chunk(seq, size):
    """
    Returns an iterator that yields full chunks seq into size chunks.

    >>> list(chunk('hello', 2))
    [('h', 'e'), ('l', 'l')]
    >>> list(chunk('hello!', 2))
    [('h', 'e'), ('l', 'l'), ('o', '!')]
    """
    return zip(*([iter(seq)] * size))


def stream_read(stream: io.BytesIO, length, path=None):
    if length < 0:
        raise StreamError("length must be non-negative, found %s" % length, path=path)
    try:
        data = stream.read(length)
    except Exception:
        raise StreamError(
            "stream.read() failed, requested {} bytes".format(length), path=path
        )
    if len(data) != length:
        raise StreamError(
            "stream read less than specified amount, expected %d, found %d"
            % (length, len(data)),
            path=path,
        )
    return data


def stream_read_entire(stream: io.BytesIO, path=None):
    try:
        return stream.read()
    except Exception:
        raise StreamError("stream.read() failed when reading until EOF", path=path)


def stream_write(stream: io.BytesIO, data: bytes, length: int = None, path: str = None):
    if length is None:
        length = len(data)
    if not isinstance(data, bytes):
        raise StringError(
            "given non-bytes value, perhaps unicode? {!r}".format(data), path=path
        )
    if length < 0:
        raise StreamError("length must be non-negative, found %s" % length, path=path)
    if len(data) != length:
        raise StreamError(
            "bytes object of wrong length, expected %d, found %d" % (length, len(data)),
            path=path,
        )
    try:
        written = stream.write(data)
    except Exception:
        raise StreamError("stream.write() failed, given {!r}".format(data), path=path)
    if written != length:
        raise StreamError(
            "stream written less than specified, expected %d, written %d"
            % (length, written),
            path=path,
        )


def stream_seek(stream: io.BytesIO, offset: int, whence: int = 0, path: str = None):
    try:
        return stream.seek(offset, whence)
    except Exception:
        raise StreamError(
            "stream.seek() failed, offset {}, whence {}".format(offset, whence),
            path=path,
        )


def stream_tell(stream: io.BytesIO, path: str = None):
    try:
        return stream.tell()
    except Exception:
        pass


def stream_size(stream: io.BytesIO):
    try:
        fallback = stream.tell()
        end = stream.seek(0, 2)
        stream.seek(fallback)
        return end
    except Exception:
        raise StreamError("stream. seek() tell() failed", path="???")


def stream_iseof(stream: io.BytesIO):
    try:
        fallback = stream.tell()
        data = stream.read(1)
        stream.seek(fallback)
        return not data
    except Exception:
        raise StreamError("stream. read() seek() tell() failed", path="???")


class BytesIOWithOffsets(io.BytesIO):
    @staticmethod
    def from_reading(
        stream: io.BytesIO, length: int, path: str
    ) -> "BytesIOWithOffsets | io.BytesIO":
        """
        Creates a new BytesIOWithOffsets instance from an existing stream

        :param io.BytesIO stream: Existing stream
        :param int length: Number of bytes to read
        :param str path: Path for error reporting

        :return: BytesIOWithOffsets instance
        """
        try:
            offset = stream_tell(stream, path)
            contents = stream_read(stream, length, path)
            return BytesIOWithOffsets(contents, stream, offset)
        except (io.UnsupportedOperation, StreamError):
            return io.BytesIO(stream_read(stream, length, path))

    def __init__(self, contents: bytes, parent_stream: io.BytesIO, offset: int):
        """
        Initialize the BytesIOWithOffsets instance

        :param bytes contents: Data
        :param io.BytesIO parent_stream: Parent stream
        :param int offset: Offset within the parent stream
        """
        super().__init__(contents)
        self.parent_stream = parent_stream
        self.parent_stream_offset = offset

    def tell(self) -> int:
        """
        Obtain the current offset from within the parent stream

        :return: Current offset
        :rtype: int
        """
        return super().tell() + self.parent_stream_offset

    def seek(self, offset: int, whence: int = io.SEEK_SET) -> int:
        """
        Move the current position to the specified offset

        :param int offset: Offset to seek to
        :param int whence: Reference point for offset (default is SEEK_SET)

        :return: Updated offset
        :rtype: int
        """
        if whence != io.SEEK_SET:
            super().seek(offset, whence)
        else:
            super().seek(offset - self.parent_stream_offset)
        return self.tell()


def find_constructs(struct, data):
    r"""
    Generator that yields the results of successful parsings of the given
    construct.
    Note: Construct must attempt to read something. Ie, don't have a Peek
    as your first subconstruct.

    Also, it's best if you have some type of validation (Const, OneOf, NoneOf, Check, etc) within your struct.
    Otherwise, it makes more sense to use a GreedyRange (the '[:]' notation) instead of this function.

    Example::

        >>> struct = Struct(
        ...     Const(b'MZ'),
        ...     'int' / Int16ul,
        ...     'string' / CString())
        >>> list(find_constructs(struct, b'\x01\x02\x03MZ\x0A\x00hello\x00\x03\x04MZ\x0B\x00world\x00\x00'))
        [(3, Container(int=10, string=u'hello')), (15, Container(int=11, string=u'world'))]
        >>> list(find_constructs(struct, b'nope'))
        []

    :param struct: construct to apply (instance of construct.Construct)
    :param data: byte string of data to search.

    :yield: tuple containing (offset with data, result Container class)
    """
    data = io.BytesIO(data)

    while True:
        offset = data.tell()
        try:
            data_element = struct.parse_stream(data)
        except (ConstructError, OverflowError):
            data.seek(offset + 1)
        else:
            yield offset, data_element

        # Test if we hit end of data.
        if data.read(1):
            data.seek(-1, os.SEEK_CUR)
        else:
            break
