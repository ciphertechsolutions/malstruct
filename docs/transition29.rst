=================
Transition to 2.9
=================


Overall
==========

**Compilation feature for faster performance!**

**Docstrings of all classes were overhauled.** Check the `Core API pages <https://malstruct.readthedocs.io/en/latest/index.html#api-reference>`_.


General classes
-------------------

All constructs: `parse build sizeof` methods take context entries ONLY as keyword parameters \*\*contextkw

All constructs: `parse_file` and `build_file` methods were added

All constructs: operator * can be used for docstrings and parsed hooks

All constructs: added `compile` and `benchmark` methods

All constructs: added `parsed` hook/callback

Compiled added (used internally)

Half was added alongside Single, Double

String* require explicit encodings, all of them support UTF16 UTF32 encodings, but PaddedString CString dropped some parameters and support only encodings explicitly listed in `possiblestringencodings`

PaddedString CString classes reimplemented using NullTerminated NullStripped

String* build empty strings into empty bytes (despite for example UTF16 encoding empty string into 2 bytes marker)

String class renamed to PaddedString

Enum FlagsEnum can merge labels from IntEnum IntFlag, from enum34 module

Enum FlagsEnum dropped `default` parameter but returns integer if no mapping found

Enum FlagsEnum can build from integers and labels, and expose labels as attributes, as bitwisable strings

FlagsEnum had parsing semantics fixed (affecting multi-bit flags)

Mapping replaced SymmetricMapping, and dropped `default` parameter

Struct Sequence FocusedSeq Union LazyStruct have new embedding semantics

Struct Sequence FocusedSeq Union LazyStruct are exposing subcons, as attributes and in _subcons context entry

Struct Sequence FocusedSeq Union LazyStruct are exposing _ _params _root _parsing _building _sizing _subcons _io _index entries in the context

EmbeddedBitStruct removed, instead use BitStruct with Bytewise-wrapped fields

Array reimplemented without Range, does not use stream.tell()

Range removed, GreedyRange does not support [:] syntax

Array GreedyRange RepeatUntil added `discard` parameter

Const has reordered parameters, `value` before `subcon`

Index added, in Miscellaneous

Pickled added, in Miscellaneous

Timestamp added, in Miscellaneous

Hex HexDump reimplemented, return bytes and not hexlified strings

Select dropped `includename` parameter

Select allows to build from none if any of its subcons can

If IfThenElse parameter `predicate` renamed to `condfunc`, and cannot be embedded

Switch updated, `default` parameter is `Pass` instead of `NoDefault`, dropped `includekey` parameter, and cannot be embedded

EmbeddedSwitch added, in Conditional

StopIf raises `StopFieldError` instead of `StopIteration`

Pointer changed size to 0, can be parsed lazily, can also select a stream from context entry

PrefixedArray parameter `lengthfield` renamed to `countfield`

FixedSized NullTerminated NullStripped added, in Tunneling

RestreamData added, in Tunneling

Transformed added, in Tunneling

ProcessXor and ProcessRotateLeft added, in Tunneling

ExprAdapter Mapping Restreamed changed parameters order (decoders before encoders)

Adapter changed parameters, added `path` parameter to `_encode _decode _validate` methods

Lazy added, in Lazy equivalents category

LazyStruct LazyArray reimplemented with new lazy parsing semantics

LazySequence LazyRange LazyField(OnDemand) removed

LazyBound remains, but changed to parameter-less lambda

Probe Debugger updated, ProbeInto removed


Support classes
--------------------

Container updated, uses `globalPrintFullStrings globalPrintFalseFlags globalPrintPrivateEntries`

Container updated, equality does not check hidden keys like _private or keys order

FlagsContainer removed

RestreamedBytesIO supports reading till EOF, enabling GreedyBytes GreedyString inside Bitwise Bytewise

HexString removed


Exceptions
-------------

Exceptions always display path information

FieldError was replaced with StreamError (raised when stream returns less than requested amount) and FormatFieldError (raised by FormatField class, for example if building Float from non-float value and struct.pack complains).

StreamError can be raised by most classes, when the stream is not seekable or tellable

StringError can be raised by classes like Bytes Const, when expected bytes but given unicode string as build value

BitIntegerError was replaced by IntegerError

Struct Sequence can raise IndexError KeyError when dictionaries are missing entries

RepeatError added

IndexFieldError added

CheckError added

NamedTupleError added

RawCopyError added
