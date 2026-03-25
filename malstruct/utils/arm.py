"""
Helper constructs for parsing the ARM instruction set.
"""

from malstruct.core import *

from malstruct.utils import elffileutils, helpers


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
    'cond' / Nibble,
    Const(1, BitsInteger(2)),  # must be '01'
    'reg_imm_offset' / Bit,              # 0 = immediate offset, 1 = register offset
    'pre_post_indexing' / Bit,           # 0 = post, 1 = pre
    'up_down' / Bit,                     # 0 = down, 1 = up
    'byte_word' / Bit,                   # 0 = word, 1 = byte
    'write_back' / Flag,
    'load_store' / Bit,                  # 0 = store, 1 = load
    'base_register' / Nibble,
    'src_dest_register' / Nibble,
    'offset' / IfThenElse(
        this.reg_imm_offset,
        Octet >> Nibble,       # shift applied to Rm >> Rm
        BitsInteger(12)
    )
)

LDR = ExprValidator(_ByteSwapped(_ldr_str_inst, reg_imm_offset=0), this.load_store == 1)


# Data Processing
_data_proc_inst = BitStruct(
    'cond' / Nibble,
    Const(0, BitsInteger(2)),  # must be '00'
    'reg_imm_operand' / Bit,             # 0 = immediate, 1 = register
    'opcode' / Enum(
        Nibble,
        AND=0x0, EOR=0x1, SUB=0x2, RSB=0x3, ADD=0x4, ADC=0x5, SBC=0x6, RSC=0x7,
        TST=0x8, TEQ=0x9, CMP=0xA, CMN=0xB, ORR=0xC, MOV=0xD, BIC=0xE, MVN=0xF,
    ),
    'set_cond' / Flag,
    'operand_1_reg' / Nibble,
    'dest_reg' / Nibble,
    'operand_2' / IfThenElse(
        this.reg_imm_operand,
        Octet >> Nibble,       # shift applied to Rm >> Rm
        Nibble >> Octet,       # rotate applied to Imm >> Imm
    ),
)
# TODO: Finish adding support for analyzing data processing instructions.
# (shifting/rotating will need to applied to the second operand)


def ELFPointer(inst, inst_end, subcon, elf=None):
    r"""
    This is the ARM version of ELFPointer.
    This subconstruct takes two arguments which
    specify the parsed ARM instruction containing an immediate offset in its second operand
    and the end offset (physical) for said instruction.

    The following ARM instructions are currently supported:
        - LDR

    Example: for the instruction "LDR  R1, =data_offset"
    spec = Struct(
        'inst' / ARM.LDR,
        'inst_end' / Tell,
        'data' / ARM.ELFPointer(this.inst, this.inst_end, Bytes(100))
    )

    spec = Struct(
        're' / Regex(
            '\x01\x03(?P<data_ldr_inst>.{4})(?P<end>)\x06\x07', data_ldr_inst=ARM.LDR, end=Tell),
        'data' / ARM.ELFPointer(this.re.data_ldr_inst, this.re.end, Bytes(100))
    )

    spec.parse(file_data, elf=elf_object)

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
            raise ConstructError('Load/Store bit must be set to 1')
        if _inst.base_register != 15 or _inst.reg_imm_offset == 1:
            raise ConstructError(
                'Only instructions with PC relative addressing is currently supported.')
        if _inst.write_back:
            raise ConstructError('Write back cannot be enabled for PC relative addressing.')
        # According to spec, PC is an address 8 bytes from the start of the instruction.
        # (Which means 4 bytes from end.)
        _elf = elf or ctx._params.elf
        _inst_end = inst_end(ctx._) if callable(inst_end) else inst_end
        _inst_end = elffileutils.obtain_memory_offset(_inst_end, elf=_elf)
        pc = _inst_end + 4
        mem_offset = pc + _inst.offset
        return mem_offset

    # HACK: FocusLast (which is FocusedSeq) will try to create a child context when it performs it's parsing.
    # The user will be unaware of this shift and can cause issues if the subcon is dynamic.
    # Therefore, patch the given subcon to use the parent context during parsing.
    # TODO: Embedded() should allow for this functionality!
    class _Embedded(Subconstruct):
        def _parse(self, stream, context, path):
            return self.subcon._parsereport(stream, context._, path)
    subcon = _Embedded(subcon)

    # Use original ELFPointer to create a pointer to the entry in the literal pool, which
    # in turn, is a pointer to the data we actually want.
    return helpers.FocusLast(
        helpers.ELFPointer(_obtain_literal_pool_mem_offset, Int32ul, elf=elf),
        helpers.ELFPointer(this[0], subcon, elf=elf),
    )
