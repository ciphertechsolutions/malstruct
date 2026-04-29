class ConstructError(Exception):
    """
    This is the root of all exceptions raised by parsing classes in this library. Note that the helper functions in lib module can raise standard ValueError (but parsing classes are not allowed to).
    """

    def __init__(self, message="", path=None):
        self.path = path
        if path is None:
            super().__init__(message)
        else:
            message = "Error in path {}\n".format(path) + message
            super().__init__(message)


class SizeofError(ConstructError):
    """
    Parsing classes sizeof() methods are only allowed to either return an integer or raise SizeofError instead. Note that this exception can mean the parsing class cannot be measured apriori in principle, however it can also mean that it just cannot be measured in these particular circumstances (eg. there is a key missing in the context dictionary at this time).
    """


class AdaptationError(ConstructError):
    """
    Currently not used.
    """


class ValidationError(ConstructError):
    """
    Validator ExprValidator derived parsing classes can raise this exception: OneOf NoneOf. It can mean that the parse or build value is or is not one of specified values.
    """


class StreamError(ConstructError):
    """
    Almost all parsing classes can raise this exception: it can mean a variety of things. Maybe requested reading negative amount, could not read enough bytes, requested writing different amount than actual data, could not write all bytes, stream is not seekable, stream is not tellable, etc. Note that there are a few parsing classes that do not use the stream to compute output and therefore do not raise this exception.
    """


class FormatFieldError(ConstructError):
    """
    Only one parsing class can raise this exception: FormatField. It can either mean the format string is invalid or the value is not valid for provided format string. See standard struct module for what is acceptable.
    """


class IntegerError(ConstructError):
    """
    Only some numeric parsing classes can raise this exception: BytesInteger BitsInteger VarInt ZigZag. It can mean either the length parameter is invalid, the value is not an integer, the value is negative or too low or too high for given parameters, or the selected endianness cannot be applied.
    """


class StringError(ConstructError):
    """
    Almost all parsing classes can raise this exception: It can mean a unicode string was ed instead of bytes, or a bytes was ed instead of a unicode string. Also some classes can raise it explicitly: PascalString CString GreedyString. It can mean no encoding or invalid encoding was selected. Note that currently, if the data cannot be encoded decoded given selected encoding then UnicodeEncodeError UnicodeDecodeError are raised, which are not rooted at ConstructError.
    """


class MappingError(ConstructError):
    """
    Few parsing classes can raise this exception: Enum FlagsEnum Mapping. It can mean the build value is not recognized and therefore cannot be mapped onto bytes.
    """


class RangeError(ConstructError):
    """
    Few parsing classes can raise this exception: Array PrefixedArray LazyArray. It can mean the count parameter is invalid, or the build object has too little or too many elements.
    """


class RepeatError(ConstructError):
    """
    Only one parsing class can raise this exception: RepeatUntil. It can mean none of the elements in build object ed the given predicate.
    """


class ConstError(ConstructError):
    """
    Only one parsing class can raise this exception: Const. It can mean the wrong data was parsed, or wrong object was built from.
    """


class IndexFieldError(ConstructError):
    """
    Only one parsing class can raise this exception: Index. It can mean the class was not nested in an array parsing class properly and therefore cannot access the _index context key.
    """


class CheckError(ConstructError):
    """
    Only one parsing class can raise this exception: Check. It can mean the condition lambda failed during a routine parsing building check.
    """


class ExplicitError(ConstructError):
    """
    Only one parsing class can raise this exception: Error. It can mean the parsing class was merely parsed or built with.
    """


class NamedTupleError(ConstructError):
    """
    Only one parsing class can raise this exception: NamedTuple. It can mean the subcon is not of a valid type.
    """


class TimestampError(ConstructError):
    """
    Only one parsing class can raise this exception: Timestamp. It can mean the subcon unit or epoch are invalid.
    """


class UnionError(ConstructError):
    """
    Only one parsing class can raise this exception: Union. It can mean none of given subcons was properly selected, or trying to build without providing a proper value.
    """


class SelectError(ConstructError):
    """
    Only one parsing class can raise this exception: Select. It can mean neither subcon succeded when parsing or building.
    """


class SwitchError(ConstructError):
    """
    Currently not used.
    """


class StopFieldError(ConstructError):
    """
    Only one parsing class can raise this exception: StopIf. It can mean the given condition was met during parsing or building.
    """


class PaddingError(ConstructError):
    """
    Multiple parsing classes can raise this exception: PaddedString Padding Padded Aligned FixedSized NullTerminated NullStripped. It can mean multiple issues: the encoded string or bytes takes more bytes than padding allows, length parameter was invalid, pattern terminator or pad is not a proper bytes value, modulus was less than 2.
    """


class TerminatedError(ConstructError):
    """
    Only one parsing class can raise this exception: Terminated. It can mean EOF was not found as expected during parsing.
    """


class RawCopyError(ConstructError):
    """
    Only one parsing class can raise this exception: RawCopy. It can mean it cannot build as both data and value keys are missing from build dict object.
    """


class RotationError(ConstructError):
    """
    Only one parsing class can raise this exception: ProcessRotateLeft. It can mean the specified group is less than 1, data is not of valid length.
    """


class ChecksumError(ConstructError):
    """
    Only one parsing class can raise this exception: Checksum. It can mean expected and actual checksum do not match.
    """


class CancelParsing(ConstructError):
    """
    This exception can only be raised explicitly by the user, and it causes the parsing class to stop what it is doing (interrupts parsing or building).
    """


class CipherError(ConstructError):
    """
    Two parsing classes can raise this exception: EncryptedSym EncryptedSymAead. It can mean none or invalid cipher object was provided.
    """


class IterError(ConstructError):
    pass
