import pefile

from malstruct.core import Adapter
from malstruct.exceptions import *
from malstruct.stream import Pointer


def _memory_to_raw_offset(memory_offset: int, pe: pefile.PE) -> int | None:
    """
    Convert a memory offset to a raw offset

    :param int memory_offset: Memory offset to convert
    :param pefile.PE pe: PE object

    :return: Converted offset
    :rtype: int
    """
    rva = memory_offset - pe.OPTIONAL_HEADER.ImageBase
    return pe.get_physical_by_rva(rva)


def _raw_to_memory_offset(raw_offset: int, pe: pefile.PE) -> int | None:
    """
    Convert a raw offset to a memory offset

    :param int raw_offset: Raw offset to convert
    :param pefile.PE pe: PE object

    :return: Converted offset
    :rtype: int
    """
    return pe.OPTIONAL_HEADER.ImageBase + pe.get_rva_from_offset(raw_offset)


def _memory_to_raw_offset_x64(
    relative_location: int, instruction_end: int, pe: pefile.PE
) -> int | None:
    """
    Given a relative location to the end of an instruction, convert the end instruction address to a memory offset
    and add that to the relative location of the data to obtain a memory offset to convert to a raw offset
    Convert a memory offset to a raw offset

    :param int relative_location: Relative location of memory offset in reference to instruction end
    :param int instruction_end: Raw offset of instruction end
    :param pefile.PE pe: PE object

    :return: Converted offset
    :rtype: int
    """
    instruction_end_memory = _raw_to_memory_offset(instruction_end, pe)
    return _memory_to_raw_offset(instruction_end_memory + relative_location, pe)


class PEPhysicalAddress(Adapter):
    r"""
    Adapter used to convert an int representing a PE memory address into a physical address.

    The PE object can either be passed into the specific construct, or as a keyword argument in
    the parse()/build() functions.
    If passed in through parse()/build(), the same PE object will be used for all instances.

    This Adapter is useful when used along-side the Pointer construct::
        >>> spec = Struct(
            'offset' / PEPhysicalAddress(Int32ul),
            'data' / Pointer(this.offset, Bytes(100))
        )
        >>> with open(r'C:\32bit_exe', 'rb') as fo:
        ...     file_data = fo.read()
        >>> pe = pefile.PE(data=file_data)
        >>> PEPhysicalAddress(Int32ul, pe=pe).build(100)
        'd\x00@\x00'
        >>> PEPhysicalAddress(Int32ul, pe=pe).parse(b'd\x00@\x00')
        100
        >>> PEPhysicalAddress(Int32ul).build(100, pe=pe)
        'd\x00@\x00'
        >>> PEPhysicalAddress(Int32ul).parse(b'd\x00@\x00', pe=pe)
        100
    """

    def __init__(self, subcon, pe: pefile.PE = None):
        """
        :param pe: Optional PE file object. (if not supplied here, this must be supplied during parse()/build()
        :param subcon: subcon to parse memory offset.
        """
        super().__init__(subcon)
        self._pe = pe

    def _encode(self, obj, context, path):
        pe = self._pe or context._params.pe
        if pe and (address := _raw_to_memory_offset(obj, pe)):
            return address
        raise ConstructError("Unable to encode physical address.")

    def _decode(self, obj, context, path):
        pe = self._pe or context._params.pe
        if pe and (address := _memory_to_raw_offset(obj, pe)):
            return address
        raise ConstructError("Unable to decode virtual address.")


class PEMemoryAddress(Adapter):
    r"""
    Adapter used to convert an int representing a PE physical address into a memory address.

    The PE object can either be passed into the specific construct, or as a keyword argument in
    the parse()/build() functions.
    If passed in through parse()/build(), the same PE object will be used for all instances.

    This Adapter is useful when used along-side the PEPointer construct::

        >>> spec = Struct(
            'relative_offset' / Int32ul,
            'instruction_end' / PEMemoryAddress(Tell),
            'data' / PEPointer(this.relative_offset + this.instruction_end, Bytes(100))
        )
    """

    def __init__(self, subcon, pe: pefile.PE = None):
        """
        :param pe: Optional PE file object. (if not supplied here, this must be supplied during parse()/build()
        :param subcon: subcon to parse physical offset.
        """
        super().__init__(subcon)
        self._pe = pe

    def _encode(self, obj, context, path):
        pe = self._pe or context._params.pe
        if pe and (address := _memory_to_raw_offset(obj, pe)):
            return address
        raise ConstructError("Unable to encode virtual address.")

    def _decode(self, obj, context, path):
        pe = self._pe or context._params.pe
        if pe and (address := _raw_to_memory_offset(obj, pe)):
            return address
        raise ConstructError("Unable to decode physical address.")


class PEAddressFromRVA(Adapter):
    r"""
    Adapter used to convert an int representing a PE relative virtual address (RVA) into a physical address.

    The PE object can either be passed into the specific construct, or as a keyword argument in the parse()/build()
    functions.
    If passed in through parse()/build(), the same PE object will be used for all instances.

    This Adapter is useful when used along-side the Pointer construct::

        >>> spec = Struct(
            'offset' / PEAddrFromRVA(Int32ul),
            'data' / Pointer(this.offset, Bytes(100))
        )
    """

    def __init__(self, subcon, pe: pefile.PE = None):
        """
        :param pe: Optional PE file object. (if not supplied here, this must be supplied during parse()/build()
        :param subcon: subcon to parse memory offset.
        """
        super().__init__(subcon)
        self._pe = pe

    def _encode(self, obj, context, path):
        pe = self._pe or context._params.pe
        if pe and (address := pe.get_rva_from_offset(obj)):
            return address
        raise ConstructError("Unable to encode physical address.")

    def _decode(self, obj, context, path):
        pe = self._pe or context._params.pe
        if pe and (address := pe.get_physical_by_rva(obj)):
            return address
        raise ConstructError("Unable to decode relative virtual address.")


def PEPointer(mem_off, subcon, pe=None):
    r"""
    This is an alternative to PEPhysicalAddress when you are using the address along with Pointer

    Example::

        # Simplifies
        >>> spec = Struct(
            'offset' / PEPhysicalAddress(Int32ul),
            'data' / Pointer(this.offset, Bytes(100))
        )

        # to
        >>> spec = Struct(
            'offset' / Int32ul,
            'data' / PEPointer(this.offset, Bytes(100))
        )
        >>> spec.parse(file_data, pe=pe_object)

    :param mem_off: an int or a function that represents the memory offset for the equivalent physical offset.
    :param subcon: the subcon to use at the offset
    :param pe: Optional PE file object. (if not supplied here, this must be supplied during parse()/build()
    """

    def _obtain_physical_offset(ctx):
        _pe = pe or ctx._params.pe
        _mem_off = mem_off(ctx) if callable(mem_off) else mem_off
        if _pe and (address := _memory_to_raw_offset(_mem_off, _pe)):
            return address
        raise ConstructError("Unable to decode virtual address")

    return Pointer(_obtain_physical_offset, subcon)


def PEPointer64(mem_off, inst_end, subcon, pe=None):
    r"""
    This is the 64-bit version of PEPointer.
    This subconstruct takes an extra argument which specifies
    the location of the end of the instruction for which the memory_offset was used.
    (A parameter necessary for 64-bit)

    Example::

        >>> spec = Struct(
            'offset' / Int32ul,
            Padding(2),
            'inst_end' / Tell,
            'data' / PEPointer64(this.offset, this.inst_end, Byte(100))
        )
        >>> spec = Struct(
            'instruction' / Regex(
                '\x01\x03(?P<data_ptr>.{4})\x04\x05(?P<end>)\x06\x07', data_ptr=DWORD, end=Tell),
            'data' / PEPointer64(this.instruction.data_ptr, this.instruction.end, Bytes(100))
        )
        >>> spec.parse(file_data, pe=pe_object)

    :param mem_off: an int or a function that represents the memory offset for the equivalent physical offset.
    :param inst_end: an int or a function that represents the location of the end of the instruction to be relative to.
    :param subcon: the subcon to use at the offset
    :param pe: Optional PE file object. (if not supplied here, this must be supplied during parse()/build()
    """

    def _obtain_physical_offset(ctx):
        _pe = pe or ctx._params.pe
        _mem_off = mem_off(ctx) if callable(mem_off) else mem_off
        _inst_end = inst_end(ctx) if callable(inst_end) else inst_end
        if _pe and (address := _memory_to_raw_offset_x64(_mem_off, _inst_end, _pe)):
            return address
        raise ConstructError("Unable to decode virtual address")

    return Pointer(_obtain_physical_offset, subcon)


def PERVAPointer(rva, subcon, pe=None):
    r"""
    This is an alternative to PEAddrFromRVA when you are using the address along with Pointer


    :param rva: an int or a function that represents the relative virtual offset for the equivalent physical offset.
    :param subcon: the subcon to use at the offset
    :param pe: Optional PE file object. (if not supplied here, this must be supplied during parse()/build()
    """

    def _obtain_physical_offset(ctx):
        _pe = pe or ctx._params.pe
        _rva = rva(ctx) if callable(rva) else rva
        try:
            if address := _pe.get_physical_by_rva(_rva):
                return address
            raise ConstructError("Unable to decode virtual address")
        # AttributeError can occur if rva is None
        except AttributeError:
            raise ConstructError(f"Unable to decode virtual address")

    return Pointer(_obtain_physical_offset, subcon)
