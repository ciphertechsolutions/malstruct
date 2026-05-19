import elftools.elf.elffile as elffile

from malstruct.adapters import ExprValidator
from malstruct.conditional import IfThenElse
from malstruct.core import Adapter, Struct, this
from malstruct.exceptions import *
from malstruct.integers import Bit, BitsInteger, Int16sb, Int32ul, Nibble, Octet
from malstruct.lib import swapbytes
from malstruct.mappings import Enum, Flag
from malstruct.miscellaneous import Const
from malstruct.stream import Pointer
from malstruct.transforms import BitStruct, FocusLast, Transformed


def _memory_to_raw_offset(memory_offset: int, elf: elffile.ELFFile) -> int | None:
    """
    Convert a memory offset to a raw offset

    :param int memory_offset: Memory offset to convert
    :param elffile.ELFFile elf: elf object

    :return: Converted offset
    :rtype: int
    """
    for offset in elf.address_offsets(memory_offset):
        return offset


def _raw_to_memory_offset(raw_offset: int, elf: elffile.ELFFile) -> int | None:
    """
    Convert a raw offset to a memory offset

    :param int raw_offset: Raw offset to convert
    :param elffile.ELFFile elf: elf object

    :return: Converted offset
    :rtype: int
    """
    for seg in elf.iter_segments():
        if seg["p_offset"] <= raw_offset < (seg["p_offset"] + seg["p_filesz"]):
            return raw_offset - seg["p_offset"] + seg["p_vaddr"]


def ELFPointer(mem_off, subcon, elf=None):
    r"""
    Pointer for ELF files. This works for both memory sizes.

    NOTE: This only works for x86 instructions. For other architectures,
    please see the "ELFPointer" within their respective submodules

    :param mem_off: an int or a function that represents the memory offset for the equivalent physical offset.
    :param subcon: the subcon to use at the offset
    :param elf: Optional elftools.ELFFile file object.
        (if not supplied here, this must be supplied during parse()/build()
    """

    def _obtain_physical_offset(ctx):
        _elf = elf or ctx._params.elf
        _mem_off = mem_off(ctx) if callable(mem_off) else mem_off
        if _elf and (address := _memory_to_raw_offset(_mem_off, _elf)):
            return address
        raise ConstructError("Unable to decode virtual address")

    return Pointer(_obtain_physical_offset, subcon)


class ELFMemoryAddress(Adapter):
    r"""
    Adapter used to convert an int representing a physical address into an ELF memory address.

    """

    def __init__(self, subcon, elf: elffile.ELFFile = None):
        """
        :param elffile.ELFFile elf: Optional ELF file object. (if not supplied here, this must be supplied during parse()/build()
        :param subcon: subcon to parse memory offset.
        """
        super().__init__(subcon)
        self._elf = elf

    def _encode(self, obj, context, path):
        _elf = self._elf or context._params.elf
        if _elf and (address := _memory_to_raw_offset(obj, _elf)):
            return address
        raise ConstructError("Unable to decode virtual address.")

    def _decode(self, obj, context, path):
        _elf = self._elf or context._params.elf
        if _elf and (address := _raw_to_memory_offset(obj, _elf)):
            return address
        raise ConstructError("Unable to encode physical address.")


def _ByteSwapped(subcon, **ctx):
    r"""
    MODIFIED version of ByteSwapped that allows providing a context.
    Swap the byte order within boundaries of the given subcon.

    :param subcon: the subcon on top of byte swapped bytes
    :param **ctx: Context passed to subcon.sizeof()

    Example::

        Int24ul <--> ByteSwapped(Int24ub)
    """
    size = subcon.sizeof(**ctx)
    return Transformed(subcon, swapbytes, size, swapbytes, size)


# Single Data Transfer (LDR, STR)
_ldr_str_inst = BitStruct(
    "cond" / Nibble,
    Const(1, BitsInteger(2)),  # must be '01'
    "reg_imm_offset" / Bit,  # 0 = immediate offset, 1 = register offset
    "pre_post_indexing" / Bit,  # 0 = post, 1 = pre
    "up_down" / Bit,  # 0 = down, 1 = up
    "byte_word" / Bit,  # 0 = word, 1 = byte
    "write_back" / Flag,
    "load_store" / Bit,  # 0 = store, 1 = load
    "base_register" / Nibble,
    "src_dest_register" / Nibble,
    "offset"
    / IfThenElse(
        this.reg_imm_offset,
        Octet >> Nibble,  # shift applied to Rm >> Rm
        BitsInteger(12),
    ),
)

LDR_ARM = ExprValidator(
    _ByteSwapped(_ldr_str_inst, reg_imm_offset=0), this.load_store == 1
)


# Data Processing
_data_proc_inst = BitStruct(
    "cond" / Nibble,
    Const(0, BitsInteger(2)),  # must be '00'
    "reg_imm_operand" / Bit,  # 0 = immediate, 1 = register
    "opcode"
    / Enum(
        Nibble,
        AND=0x0,
        EOR=0x1,
        SUB=0x2,
        RSB=0x3,
        ADD=0x4,
        ADC=0x5,
        SBC=0x6,
        RSC=0x7,
        TST=0x8,
        TEQ=0x9,
        CMP=0xA,
        CMN=0xB,
        ORR=0xC,
        MOV=0xD,
        BIC=0xE,
        MVN=0xF,
    ),
    "set_cond" / Flag,
    "operand_1_reg" / Nibble,
    "dest_reg" / Nibble,
    "operand_2"
    / IfThenElse(
        this.reg_imm_operand,
        Octet >> Nibble,  # shift applied to Rm >> Rm
        Nibble >> Octet,  # rotate applied to Imm >> Imm
    ),
)
# TODO: Finish adding support for analyzing data processing instructions.
# (shifting/rotating will need to applied to the second operand)


def ELFPointerARM(inst, inst_end, subcon, elf=None):
    r"""
    This is the ARM version of ELFPointer.
    This subconstruct takes two arguments which
    specify the parsed ARM instruction containing an immediate offset in its second operand
    and the end offset (physical) for said instruction.

    The following ARM instructions are currently supported:
    - LDR

    Example: for the instruction "LDR  R1, =data_offset"::

        >>> spec = Struct(
            'inst' / LDR_ARM,
            'inst_end' / Tell,
            'data' / ELFPointerARM(this.inst, this.inst_end, Bytes(100))
        )
        >>> spec = Struct(
            're' / Regex(
                '\x01\x03(?P<data_ldr_inst>.{4})(?P<end>)\x06\x07', data_ldr_inst=LDR_ARM, end=Tell),
            'data' / ELFPointerARM(this.re.data_ldr_inst, this.re.end, Bytes(100))
        )
        >>> spec.parse(file_data, elf=elf_object)

    :param inst: a Container or function that represents the assembly instruction
    :param inst_end: an int or a function that represents the location of the end of the instruction.
    :param subcon: the subcon to use at the offset
    :param elf: Optional elftools.ELFFile file object.
        (if not supplied here, this must be supplied during parse()/build()
    """

    def _obtain_literal_pool_mem_offset(ctx):
        """Obtains the memory offset to the entry in the literal pool."""
        # Validate LDR instruction
        _inst = inst(ctx._) if callable(inst) else inst
        if _inst.load_store != 1:
            raise ConstructError("Load/Store bit must be set to 1")
        if _inst.base_register != 15 or _inst.reg_imm_offset == 1:
            raise ConstructError(
                "Only instructions with PC relative addressing is currently supported."
            )
        if _inst.write_back:
            raise ConstructError(
                "Write back cannot be enabled for PC relative addressing."
            )
        # According to spec, PC is an address 8 bytes from the start of the instruction.
        # (Which means 4 bytes from end.)
        _elf = elf or ctx._params.elf
        _inst_end = inst_end(ctx._) if callable(inst_end) else inst_end
        if _elf and (_inst_end := _raw_to_memory_offset(_inst_end, elf=_elf)):
            pc = _inst_end + 4
            mem_offset = pc + _inst.offset
            return mem_offset
        raise ConstructError("Failed to convert PC relative address")

    # Use original ELFPointer to create a pointer to the entry in the literal pool, which
    # in turn, is a pointer to the data we actually want.
    return FocusLast(
        ELFPointer(_obtain_literal_pool_mem_offset, Int32ul, elf=elf),
        ELFPointer(this[0], subcon, elf=elf),
    )


"""
Helper constructs for parsing the MIPS instruction set.

reference: github.com/MIPT-ILab/mipt-mips/wiki/MIPS-Instruction-Set
"""


_REGISTERS = {
    "$zero": 0,
    "$at": 1,
    "$v0": 2,
    "$v1": 3,
    "$a0": 4,
    "$a1": 5,
    "$a2": 6,
    "$a3": 7,
    "$t0": 8,
    "$t1": 9,
    "$t2": 10,
    "$t3": 11,
    "$t4": 12,
    "$t5": 13,
    "$t6": 14,
    "$t7": 15,
    "$s0": 16,
    "$s1": 17,
    "$s2": 18,
    "$s3": 19,
    "$s4": 20,
    "$s5": 21,
    "$s6": 22,
    "$s7": 23,
    "$t8": 24,
    "$t9": 25,
    "$k0": 26,
    "$k1": 27,
    "$gp": 28,
    "$sp": 29,
    "$fp": 30,
    "$ra": 31,
}
_Register = Enum(BitsInteger(5), **_REGISTERS)

# I-type instruction
_I_inst = Struct(
    *BitStruct(
        "opcode"
        / Enum(
            BitsInteger(6),
            # NOTE: Some opcode values are reserved for other instruction formats
            # and we should let construct fail if it sees one.
            j=0x02,
            jal=0x03,
            beq=0x04,
            bne=0x05,
            blez=0x06,
            bgtz=0x07,
            addi=0x08,
            addiu=0x09,
            slti=0x0A,
            sltiu=0x0B,
            andi=0x0C,
            ori=0x0D,
            xori=0x0E,
            lui=0x0F,
            beql=0x14,
            bnel=0x15,
            blezl=0x16,
            bgtzl=0x17,
            daddi=0x18,
            daddiu=0x19,
            ldl=0x1A,
            ldr=0x1B,
            jalx=0x1D,
            lb=0x20,
            lh=0x21,
            lwl=0x22,
            lw=0x23,
            lbu=0x24,
            lhu=0x25,
            lwr=0x26,
            lwu=0x27,
            sb=0x28,
            sh=0x29,
            swl=0x2A,
            sw=0x2B,
            sdl=0x2C,
            sdr=0x2D,
            swr=0x2E,
            cache=0x2F,
            ll=0x30,
            lwc1=0x31,
            lwc2=0x32,
            pref=0x33,
            lld=0x34,
            ldc1=0x35,
            ldc2=0x36,
            ld=0x37,
            sc=0x38,
            swc1=0x39,
            swc2=0x3A,
            scd=0x3C,
            sdc1=0x3D,
            sdc2=0x3E,
            sd=0x3F,
        ),
        "src_register" / _Register,
        "target_register" / _Register,
        # 'imm_constant' / construct.BitsInteger(16)
    ),
    # Need to move immediate outside of BitStruct to create signed number.
    # (Luckly, the constant is byte aligned)
    "imm_constant" / Int16sb,
)


lw = ExprValidator(_I_inst, this.opcode == "lw")


def MIPSPointer(high, rel_off, subcon, elf=None):
    r"""
    Pointer for MIPS binaries

    Convert the high value and add the relative offset to obtain the memory offset of the data. Convert the memory
    offset to a physical offset and obtain the targeted information using the provided subcon

    :param high: High 16-bits
    :param rel_off: Relative information offset
    :param subcon: the subcon to use at the offset
    :param elf: Optional elftools.ELFFile file object.
    """

    def _obtain_physical_offset(ctx):
        _elf = elf or ctx._params.elf
        _high = high(ctx) if callable(high) else high
        _rel_off = rel_off(ctx) if callable(rel_off) else rel_off

        _mem_off = (_high << 16) + _rel_off
        if _elf and (phy_off := _memory_to_raw_offset(_mem_off, _elf)):
            return phy_off

        raise ConstructError("Unable to decode virtual address")

    return Pointer(_obtain_physical_offset, subcon)


def MIPSGOTPointer(start, high, low, rel_off, subcon, elf=None):
    r"""
    Pointer for MIPS binaries using .got

    If the MIPS binary uses an indirect lookup, the start of the function is a relative pointer to the .got segment,
    which contains an information list. Calculate the address of the .got segment by adding the start of the function
    to the high and low addresses, and then add the relative offset of the targeted entry. Parse using the subcon to
    obtain the targeted information address

    :param start: Start offset for reference function
    :param high: High 16-bits
    :param low: Low 16-bits
    :param rel_off: Relative information offset
    :param subcon: the subcon to use at the offset
    :param elf: Optional elftools.ELFFile file object.
    """

    def _obtain_physical_offset(ctx):
        _elf = elf or ctx._params.elf
        _start = start(ctx) if callable(start) else start
        _high = high(ctx) if callable(high) else high
        _low = low(ctx) if callable(low) else low
        _rel_off = rel_off(ctx) if callable(rel_off) else rel_off

        _mem_off = _start + (_high << 16) + _low + _rel_off
        if _elf and (phy_off := _memory_to_raw_offset(_mem_off, _elf)):
            return phy_off
        raise ConstructError("Unable to decode virtual address")

    return Pointer(_obtain_physical_offset, subcon)
