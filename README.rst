Malstruct
===================

Malstruct is a powerful **declarative** and **symmetrical** parser and builder for binary data that was forked from `construct <https://github.com/construct/construct>`_ as of release 2.10.70.

Instead of writing *imperative code* to parse a piece of data, you declaratively define a *data structure* that describes your data. As this data structure is not code, you can use it in one direction to *parse* data into Pythonic objects, and in the other direction, to *build* objects into binary data.

The library provides both simple, atomic constructs (such as integers of various sizes), as well as composite ones which allow you form hierarchical and sequential structures of increasing complexity. Construct features **bit and byte granularity**, easy debugging and testing, an **easy-to-extend subclass system**, and lots of primitive constructs to make your work easier:

* Fields: raw bytes or numerical types
* Structs and Sequences: combine simpler constructs into more complex ones
* Bitwise: splitting bytes into bit-grained fields
* Adapters: change how data is represented
* Arrays/Ranges: duplicate constructs
* Meta-constructs: use the context (history) to compute the size of data
* If/Switch: branch the computational path based on the context
* On-demand (lazy) parsing: read and parse only what you require
* Pointers: jump from here to there in the data stream
* Tunneling: prefix data with a byte count or compress it


Example
---------

A ``Struct`` is a collection of ordered, named fields::

    >>> format = Struct(
    ...     "signature" / Const(b"BMP"),
    ...     "width" / Int8ub,
    ...     "height" / Int8ub,
    ...     "pixels" / Array(this.width * this.height, Byte),
    ... )
    >>> format.build(dict(width=3,height=2,pixels=[7,8,9,11,12,13]))
    b'BMP\x03\x02\x07\x08\t\x0b\x0c\r'
    >>> format.parse(b'BMP\x03\x02\x07\x08\t\x0b\x0c\r')
    Container(signature=b'BMP')(width=3)(height=2)(pixels=[7, 8, 9, 11, 12, 13])

A ``Sequence`` is a collection of ordered fields, and differs from ``Array`` and ``GreedyRange`` in that those two are homogenous::

    >>> format = Sequence(PascalString(Byte, "utf8"), GreedyRange(Byte))
    >>> format.build([u"lalaland", [255,1,2]])
    b'\nlalaland\xff\x01\x02'
    >>> format.parse(b"\x004361789432197")
    ['', [52, 51, 54, 49, 55, 56, 57, 52, 51, 50, 49, 57, 55]]


Malware Analysis
----------------

Helpers and utilities have been added to Malstruct to aid in malware analysis and configuration parser development, from simple `windows structure extensions <https://github.com/ciphertechsolutions/malstruct/tree/master/src/malstruct/windows/structures.py>`_ to constructs/adapters to aid in processing binary file types (e.g. PE, ELF, and Mach-O).

For example, when attempting to extract a referenced string from a 64-bit PE file the following can assist::

    >>> spec = FocusLast(
        "re" / RegexSearch(
            re.compile(
                # test64.exe @ 0x14000101d
                br"""
                    \x45\x33\xc9                    # xor     r9d, r9d; lpNumberOfCharsWritten
                    \x41\xb8(?P<size>.{4})          # mov     r8d, 0Eh; nNumberOfCharsToWrite
                    \x48\x8d\x15(?P<ro>.{4})(?P<e>) # lea     rdx, aHelloWorld; "Hello, World!\n"
                    \x48\x8b\x4c\x24.               # mov     rcx, [rsp+48h+hConsoleOutput]; hConsoleOutput
                    \xff\x15.{4}                    # call    cs:WriteConsoleA
                    \x33\xc9                        # xor     ecx, ecx; uExitCode
                """,
                re.DOTALL | re.VERBOSE
            ),
            size=Int32ul,
            ro=Int32ul,
            e=Tell
        ),
        PEPointer64(this.re.ro, this.re.e, String(this.re.size))
    )
    >>> spec.parse(data, pe=pe)
    'Hello, World!\n'


Alternatively to using `PEPointer64`, users can leverage the `PEMemoryAddress` adapter to perform the internal memory conversion calculation as follows::

    >>> spec = FocusLast(
        "re" / RegexSearch(
            re.compile(
                # test64.exe @ 0x14000101d
                br"""
                    \x45\x33\xc9                    # xor     r9d, r9d; lpNumberOfCharsWritten
                    \x41\xb8(?P<size>.{4})          # mov     r8d, 0Eh; nNumberOfCharsToWrite
                    \x48\x8d\x15(?P<ro>.{4})(?P<e>) # lea     rdx, aHelloWorld; "Hello, World!\n"
                    \x48\x8b\x4c\x24.               # mov     rcx, [rsp+48h+hConsoleOutput]; hConsoleOutput
                    \xff\x15.{4}                    # call    cs:WriteConsoleA
                    \x33\xc9                        # xor     ecx, ecx; uExitCode
                """,
                re.DOTALL | re.VERBOSE
            ),
            size=Int32ul,
            ro=Int32ul,
            e=PEMemoryAddress(Tell)
        ),
        PEPointer(this.re.ro + this.re.e, String(this.re.size))
    )
    >>> spec.parse(data, pe=pe)
    'Hello, World!\n'



PEcon
-----
Included in malstruct is the `pecon` (PE file reconstruction utility) package. Please see the `pecon API documentation <https://malstruct.readthedocs.io/en/latest/api/pecon.html>`_ for more information.
