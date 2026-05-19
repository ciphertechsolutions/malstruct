import lief

from malstruct.core import Adapter
from malstruct.exceptions import *
from malstruct.stream import Pointer


def _obtain_fat_memory_offset(offset: int, macho: lief.MachO.FatBinary) -> int | None:
    """
    Obtain a FatBinary memory offset

    :param int offset: Physical offset
    :param lief.MachO.FatBinary macho: Mach-O object

    :return: Memory offset
    :rtype: int
    """
    for idx in range(macho.size):
        macho_bin = macho.at(idx)
        # Difference from obtain_memory_offset
        if mem_off := macho_bin.offset_to_virtual_address(
            offset - macho_bin.fat_offset
        ):
            if mem_off != 0xFFFFFFFFFFFFFFFF:
                return mem_off


def _obtain_fat_physical_offset(
    mem_offset: int, macho: lief.MachO.FatBinary
) -> int | None:
    """
    Obtain a FatBinary physical offset

    :param int mem_offset: Memory offset
    :param lief.MachO.FatBinary macho: Mach-O object

    :return: Physical offset
    :rtype: int
    """
    for idx in range(macho.size):
        macho_bin = macho.at(idx)
        if macho_bin.is_valid_addr(mem_offset):
            offset = macho_bin.virtual_address_to_offset(mem_offset)
            # 0xffffffffffffffff indicates an offset was not properly converted
            if offset != 0xFFFFFFFFFFFFFFFF:
                return offset + macho_bin.fat_offset


def _obtain_memory_offset(offset: int, macho: lief.MachO.FatBinary) -> int | None:
    """
    Obtain a memory offset

    :param int offset: Physical offset
    :param lief.MachO.FatBinary macho: Mach-O object

    :return: Memory offset
    :rtype: int
    """
    for idx in range(macho.size):
        macho_bin = macho.at(idx)
        if mem_off := macho_bin.offset_to_virtual_address(offset):
            if mem_off != 0xFFFFFFFFFFFFFFFF:
                return mem_off


def _obtain_physical_offset(mem_offset: int, macho: lief.MachO.FatBinary) -> int | None:
    """
    Obtain a physical offset

    :param int mem_offset: Memory offset
    :param lief.MachO.FatBinary macho: Mach-O object

    :return: Physical offset
    :rtype: int
    """
    for idx in range(macho.size):
        macho_bin = macho.at(idx)
        if macho_bin.is_valid_addr(mem_offset):
            offset = macho_bin.virtual_address_to_offset(mem_offset)
            # 0xffffffffffffffff indicates an offset was not properly converted
            if offset != 0xFFFFFFFFFFFFFFFF:
                return offset


def MachOPointer(mem_off, subcon, macho=None):
    r"""
    Converts a MachO.Binary virtual address to an offset

    Example::

        >>> spec = Struct(
            'offset' / Int64ul,
            'data' / MachOPointer(this.offset, Bytes(100))
        )

        >>> spec.parse(file_data, macho=macho_object)

    :param mem_off: an int or a function that represents the memory offset for the equivalent physical offset.
    :param subcon: the subcon to use at the offset
    :param macho: Optional MachO file object. (if not supplied here, this must be supplied during parse()/build()
    """

    def _obtain_physical_offset(ctx):
        _macho = macho or ctx._params.macho
        _mem_off = mem_off(ctx) if callable(mem_off) else mem_off
        if _macho is None:
            raise ConstructError("Input file is not Mach-O")
        # Iterate the binaries to find one which contains the memory address range
        for idx in range(_macho.size):
            mbin = _macho.at(idx)
            if mbin.is_valid_addr(_mem_off):
                offset = mbin.virtual_address_to_offset(_mem_off)
                # 0xffffffffffffffff indicates an offset was not properly converted
                if offset != 0xFFFFFFFFFFFFFFFF:
                    return offset
        raise ConstructError("Unable to decode virtual address")

    return Pointer(_obtain_physical_offset, subcon)


def MachOFatPointer(mem_off, subcon, macho=None):
    r"""
    Converts a MachO.Binary virtual address to an offset, offset by the start of the MachO binary

    :param mem_off: an int or a function that represents the memory offset for the equivalent physical offset.
    :param subcon: the subcon to use at the offset
    :param macho: Optional MachO file object. (if not supplied here, this must be supplied during parse()/build()
    """

    def _obtain_physical_offset(ctx):
        _macho = macho or ctx._params.macho
        _mem_off = mem_off(ctx) if callable(mem_off) else mem_off
        if _macho is None:
            raise ConstructError("Input file is not Mach-O")
        # Iterate the binaries to find one which contains the memory address range
        for idx in range(_macho.size):
            mbin = _macho.at(idx)
            if mbin.is_valid_addr(_mem_off):
                offset = mbin.virtual_address_to_offset(_mem_off)
                # 0xffffffffffffffff indicates an offset was not properly converted
                if offset != 0xFFFFFFFFFFFFFFFF:
                    # Difference from MachOPointer
                    return offset + mbin.fat_offset
        raise ConstructError("Unable to decode virtual address")

    return Pointer(_obtain_physical_offset, subcon)


class MachOMemoryAddress(Adapter):
    r"""
    Adapter used to convert an int representing an MachO memory address into a physical address.

    """

    def __init__(self, subcon, macho=None):
        """
        :param macho: Optional MachO file object. (if not supplied here, this must be supplied during parse()/build()
        :param subcon: subcon to parse memory offset.
        """
        super().__init__(subcon)
        self._macho = macho

    def _encode(self, obj, context, path):
        macho = self._macho or context._params.macho
        if macho is None:
            raise ConstructError("Input file is not Mach-O")
        if address := _obtain_physical_offset(obj, macho=macho):
            return address
        raise ConstructError("Unable to decode virtual address.")

    def _decode(self, obj, context, path):
        macho = self._macho or context._params.macho
        if macho is None:
            raise ConstructError("Input file is not Mach-O")
        if address := _obtain_memory_offset(obj, macho=macho):
            return address
        raise ConstructError("Unable to encode physical address.")


class MachOFatMemoryAddress(Adapter):
    r"""
    Adapter used to convert an int representing an MachO memory address into a physical address, offset by the start of
    the MachO binary

    """

    def __init__(self, subcon, macho=None):
        """
        :param macho: Optional MachO file object. (if not supplied here, this must be supplied during parse()/build()
        :param subcon: subcon to parse memory offset.
        """
        super().__init__(subcon)
        self._macho = macho

    def _encode(self, obj, context, path):
        macho = self._macho or context._params.macho
        if macho is None:
            raise ConstructError("Input file is not Mach-O")
        if address := _obtain_fat_physical_offset(obj, macho=macho):
            return address
        raise ConstructError("Unable to decode virtual address.")

    def _decode(self, obj, context, path):
        macho = self._macho or context._params.macho
        if macho is None:
            raise ConstructError("Input file is not Mach-O")
        if address := _obtain_fat_memory_offset(obj, macho=macho):
            return address
        raise ConstructError("Unable to encode physical address.")
