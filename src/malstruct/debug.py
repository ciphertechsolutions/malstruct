import pdb
import sys
import traceback

from malstruct.lib import hexdump

from .core import Construct, Struct, Subconstruct, this
from .integers import Byte


class Probe(Construct):
    r"""
    Probe that dumps the context, and some stream content (peeks into it) to the screen to aid the debugging process. It can optionally limit itself to a single context entry, instead of printing entire context.
        - The lookahead stream is enabled by default
        - Use hexdump instead of hexlify to display lookahead stream
        - Allows for setting a name

    :param into: optional, None by default, or context lambda
    :param lookahead: optional, integer, number of bytes to dump from the stream

    Example::

        >>> d = Struct(
        ...     "count" / Byte,
        ...     "items" / Byte[this.count],
        ...     Probe(lookahead=32),
        ... )
        >>> d.parse(b"\x05abcde\x01\x02\x03")

        --------------------------------------------------
        Probe, path is (parsing), into is None
        Stream peek: (hexlified) b'010203'...
        Container:
            count = 5
            items = ListContainer:
                97
                98
                99
                100
                101
        --------------------------------------------------

    ::

        >>> d = Struct(
        ...     "count" / Byte,
        ...     "items" / Byte[this.count],
        ...     Probe(this.count),
        ... )
        >>> d.parse(b"\x05abcde\x01\x02\x03")

        --------------------------------------------------
        Probe, path is (parsing), into is this.count
        5
        --------------------------------------------------

    """

    def __init__(self, into=None, lookahead=128, name=None):
        self.print_name = name
        super().__init__()
        self.flagbuildnone = True
        self.into = into
        self.lookahead = lookahead

    def _parse(self, stream, context, path):
        self.printout(stream, context, path)

    def _build(self, obj, stream, context, path):
        self.printout(stream, context, path)

    def _sizeof(self, context, path):
        self.printout(None, context, path)
        return 0

    def printout(self, stream, context, path):
        print("--------------------------------------------------")
        print(f"Probe {self.print_name or ''}")
        print(f"Path: {path}")
        if self.into:
            print(f"Into: {self.into!r}")

        if self.lookahead and stream is not None:
            fallback = stream.tell()
            stream_bytes = stream.read(self.lookahead)
            stream.seek(fallback)
            if stream_bytes:
                print("Stream peek:\n{}".format(hexdump(stream_bytes, 32)))
            else:
                print("Stream peek: EOF reached")

        if context is not None:
            if self.into:
                try:
                    subcontext = self.into(context)
                    print(subcontext)
                except Exception:
                    print(
                        "Failed to compute {!r} on the context {!r}".format(
                            self.into, context
                        )
                    )
            else:
                print(context)
        print("--------------------------------------------------")


class Debugger(Subconstruct):
    r"""
    PDB-based debugger. When an exception occurs in the subcon, a debugger will appear and allow you to debug the error (and even fix it on-the-fly).

    :param subcon: Construct instance, subcon to debug

    Example::

        >>> Debugger(Byte[3]).build([])

        --------------------------------------------------
        Debugging exception of <Array: None>
        path is (building)
          File "/media/ciphertechsolutions/MAIN/GitHub/ciphertechsolutions/malstruct/debug.py", line 192, in _build
            return self.subcon._build(obj, stream, context, path)
          File "/media/ciphertechsolutions/MAIN/GitHub/ciphertechsolutions/malstruct/core.py", line 2149, in _build
            raise RangeError("expected %d elements, found %d" % (count, len(obj)))
        malstruct.core.RangeError: expected 3 elements, found 0

        > /media/ciphertechsolutions/MAIN/GitHub/ciphertechsolutions/malstruct/core.py(2149)_build()
        -> raise RangeError("expected %d elements, found %d" % (count, len(obj)))
        (Pdb) q
        --------------------------------------------------
    """

    def _parse(self, stream, context, path):
        try:
            return self.subcon._parse(stream, context, path)
        except Exception:
            self.retval = NotImplemented
            self.handle_exc(
                path,
                msg="(you can set self.retval, which will be returned from method)",
            )
            if self.retval is NotImplemented:
                raise
            else:
                return self.retval

    def _build(self, obj, stream, context, path):
        try:
            return self.subcon._build(obj, stream, context, path)
        except Exception:
            self.handle_exc(path)

    def _sizeof(self, context, path):
        try:
            return self.subcon._sizeof(context, path)
        except Exception:
            self.handle_exc(path)

    def handle_exc(self, path, msg=None):
        print("--------------------------------------------------")
        print("Debugging exception of {!r}".format(self.subcon))
        print("path is {}".format(path))
        print("".join(traceback.format_exception(*sys.exc_info())[1:]))
        if msg:
            print(msg)
        pdb.post_mortem(sys.exc_info()[2])
        print("--------------------------------------------------")
