"""
A central location to store common windows enumerations.
"""

from __future__ import absolute_import, division

import datetime

from malstruct import core as malstruct
from malstruct.core import this, len_

from . import network, datetime_, windows_enums
from malstruct.utils.windows_constants import *


"""PEFILE STRUCTURES"""

IMAGE_DOS_HEADER = malstruct.Struct(
    "e_magic" / malstruct.Default(malstruct.Bytes(2), b"MZ"),
    "e_cblp" / malstruct.Int16ul,
    "e_cp" / malstruct.Int16ul,
    "e_crlc" / malstruct.Int16ul,
    "e_cparhdr" / malstruct.Int16ul,
    "e_mimalloc" / malstruct.Int16ul,
    "e_maxalloc" / malstruct.Int16ul,
    "e_ss" / malstruct.Int16ul,
    "e_sp" / malstruct.Int16ul,
    "e_csum" / malstruct.Int16ul,
    "e_ip" / malstruct.Int16ul,
    "e_cs" / malstruct.Int16ul,
    "e_lfarlc" / malstruct.Int16ul,
    "e_ovno" / malstruct.Int16ul,
    "e_res1" / malstruct.Bytes(8),
    "e_oemid" / malstruct.Int16ul,
    "e_oeminfo" / malstruct.Int16ul,
    "e_res2" / malstruct.Bytes(20),
    "e_lfanew" / malstruct.Int32ul
)


IMAGE_SECTION_HEADER = malstruct.Struct(
    "Name" / malstruct.String(8),
    "VirtualSize" / malstruct.Int32ul,  # alias "PhysicalAddress"
    "VirtualAddress" / malstruct.Int32ul,
    "SizeOfRawData" / malstruct.Int32ul,
    "PointerToRawData" / malstruct.Int32ul,
    "PointerToRelocations" / malstruct.Default(malstruct.Int32ul, 0),
    "PointerToLinenumbers" / malstruct.Default(malstruct.Int32ul, 0),
    "NumberOfRelocations" / malstruct.Default(malstruct.Int16ul, 0),
    "NumberOfLinenumbers" / malstruct.Default(malstruct.Int16ul, 0),
    "Characteristics" / malstruct.FlagsEnum(
        malstruct.Int32ul,
        IMAGE_SCN_TYPE_NO_PAD=0x00000008,
        IMAGE_SCN_CNT_CODE=0x00000020,
        IMAGE_SCN_CNT_INITIALIZED_DATA=0x00000040,
        IMAGE_SCN_CNT_UNINITIALIZED_DATA=0x00000080,
        IMAGE_SCN_LNK_OTHER=0x00000100,
        IMAGE_SCN_LNK_INFO=0x00000200,
        IMAGE_SCN_LNK_REMOVE=0x00000800,
        IMAGE_SCN_LNK_COMDAT=0x00001000,
        IMAGE_SCN_NO_DEFER_SPEC_EXC=0x00004000,
        IMAGE_SCN_GPREL=0x00008000,
        IMAGE_SCN_MEM_PURGEABLE=0x00020000,
        IMAGE_SCN_MEM_LOCKED=0x00040000,
        IMAGE_SCN_MEM_PRELOAD=0x00080000,
        IMAGE_SCN_ALIGN_1BYTES=0x00100000,
        IMAGE_SCN_ALIGN_2BYTES=0x00200000,
        IMAGE_SCN_ALIGN_4BYTES=0x00300000,
        IMAGE_SCN_ALIGN_8BYTES=0x00400000,
        IMAGE_SCN_ALIGN_16BYTES=0x00500000,
        IMAGE_SCN_ALIGN_32BYTES=0x00600000,
        IMAGE_SCN_ALIGN_64BYTES=0x00700000,
        IMAGE_SCN_ALIGN_128BYTES=0x00800000,
        IMAGE_SCN_ALIGN_256BYTES=0x00900000,
        IMAGE_SCN_ALIGN_512BYTES=0x00A00000,
        IMAGE_SCN_ALIGN_1024BYTES=0x00B00000,
        IMAGE_SCN_ALIGN_2048BYTES=0x00C00000,
        IMAGE_SCN_ALIGN_4096BYTES=0x00D00000,
        IMAGE_SCN_ALIGN_8192BYTES=0x00E00000,
        IMAGE_SCN_LNK_NRELOC_OVFL=0x01000000,
        IMAGE_SCN_MEM_DISCARDABLE=0x02000000,
        IMAGE_SCN_MEM_NOT_CACHED=0x04000000,
        IMAGE_SCN_MEM_NOT_PAGED=0x08000000,
        IMAGE_SCN_MEM_SHARED=0x10000000,
        IMAGE_SCN_MEM_EXECUTE=0x20000000,
        IMAGE_SCN_MEM_READ=0x40000000,
        IMAGE_SCN_MEM_WRITE=0x80000000,
    )
)

IMAGE_DATA_DIRECTORY = malstruct.Struct(
    "VirtualAddress" / malstruct.Int32ul,
    "Size" / malstruct.Int32ul,
)

IMAGE_EXPORT_DIRECTORY = malstruct.Struct(
    "Characteristics" / malstruct.Default(malstruct.Int32ul, 0),
    "TimeDateStamp" / datetime_.EpochTime,
    "MajorVersion" / malstruct.Int16ul,
    "MinorVersion" / malstruct.Int16ul,
    "Name" / malstruct.Int32ul,  # rva pointer to the name
    "Base" / malstruct.Int32ul,
    "NumberOfFunctions" / malstruct.Int32ul,
    "NumberOfNames" / malstruct.Int32ul,
    "AddressOfFunctions" / malstruct.Int32ul,
    "AddressOfNames" / malstruct.Int32ul,
    "AddressOfNameOrdinals" / malstruct.Int32ul,
)

IMAGE_IMPORT_DESCRIPTOR = malstruct.Struct(
    "Characteristics" / malstruct.Int32ul,
    "TimeDateStamp" / malstruct.Int32ul,
    "ForwarderChain" / malstruct.Int32ul,
    "Name" / malstruct.Int32ul,  # rva pointer to the name
    "FirstThunk" / malstruct.Int32ul,
)

IMAGE_OPTIONAL_HEADER = malstruct.Struct(
    "Magic" / malstruct.OneOf(malstruct.Int16ul, [
        IMAGE_NT_OPTIONAL_HDR32_MAGIC, IMAGE_NT_OPTIONAL_HDR64_MAGIC, IMAGE_ROM_OPTIONAL_HDR_MAGIC]),
    "MajorLinkerVersion" / malstruct.Byte,
    "MinorLinkerVersion" / malstruct.Byte,
    "SizeOfCode" / malstruct.Int32ul,
    "SizeOfInitializedData" / malstruct.Int32ul,
    "SizeOfUninitializedData" / malstruct.Int32ul,
    "AddressOfEntryPoint" / malstruct.Int32ul,
    "BaseOfCode" / malstruct.Int32ul,
    "BaseOfData" / malstruct.If(this.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC, malstruct.Int32ul),
    "ImageBase" / malstruct.IfThenElse(
        this.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC, malstruct.Int64ul, malstruct.Int32ul
    ),
    "SectionAlignment" / malstruct.Int32ul,
    "FileAlignment" / malstruct.Int32ul,
    "MajorOperatingSystemVersion" / malstruct.Int16ul,
    "MinorOperatingSystemVersion" / malstruct.Int16ul,
    "MajorImageVersion" / malstruct.Int16ul,
    "MinorImageVersion" / malstruct.Int16ul,
    "MajorSubsystemVersion" / malstruct.Int16ul,
    "MinorSubsystemVersion" / malstruct.Int16ul,
    "Win32VersionValue" / malstruct.Default(malstruct.Int32ul, 0),  # must be 0
    "SizeOfImage" / malstruct.Int32ul,
    "SizeOfHeaders" / malstruct.Int32ul,
    "CheckSum" / malstruct.Int32ul,
    # TODO: Use enums instead?
    "Subsystem" / malstruct.OneOf(malstruct.Int16ul, [
        IMAGE_SUBSYSTEM_UNKNOWN,
        IMAGE_SUBSYSTEM_NATIVE,
        IMAGE_SUBSYSTEM_WINDOWS_GUI,
        IMAGE_SUBSYSTEM_WINDOWS_CUI,
        IMAGE_SUBSYSTEM_OS2_CUI,
        IMAGE_SUBSYSTEM_POSIX_CUI,
        IMAGE_SUBSYSTEM_WINDOWS_CE_GUI,
        IMAGE_SUBSYSTEM_EFI_APPLICATION,
        IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER,
        IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER,
        IMAGE_SUBSYSTEM_EFI_ROM,
        IMAGE_SUBSYSTEM_XBOX,
        IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION,
    ]),
    "DllCharacteristics" / malstruct.FlagsEnum(
        malstruct.Int16ul,
        IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA=0x0020,
        IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE=0x0040,
        IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY=0x0080,
        IMAGE_DLLCHARACTERISTICS_NX_COMPAT=0x0100,
        IMAGE_DLLCHARACTERISTICS_NO_ISOLATION=0x0200,
        IMAGE_DLLCHARACTERISTICS_NO_SEH=0x0400,
        IMAGE_DLLCHARACTERISTICS_NO_BIND=0x0800,
        IMAGE_DLLCHARACTERISTICS_APPCONTAINER=0x1000,
        IMAGE_DLLCHARACTERISTICS_WDM_DRIVER=0x2000,
        IMAGE_DLLCHARACTERISTICS_GUARD_CF=0x4000,
        IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE=0x8000,
    ),
    "SizeOfStackReserve" / malstruct.IfThenElse(
        this.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC, malstruct.Int64ul, malstruct.Int32ul
    ),
    "SizeOfStackCommit" / malstruct.IfThenElse(
        this.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC, malstruct.Int64ul, malstruct.Int32ul
    ),
    "SizeOfHeapReserve" / malstruct.IfThenElse(
        this.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC, malstruct.Int64ul, malstruct.Int32ul
    ),
    "SizeOfHeapCommit" / malstruct.IfThenElse(
        this.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC, malstruct.Int64ul, malstruct.Int32ul
    ),
    "LoaderFlags" / malstruct.Int32ul,
    "NumberOfRvaAndSizes" / malstruct.Rebuild(malstruct.Int32ul, malstruct.len_(this.DataDirectory)),
    "DataDirectory" / malstruct.Default(IMAGE_DATA_DIRECTORY[this.NumberOfRvaAndSizes], DEFAULT_DATA_DIRECTORIES[:]),
)

IMAGE_FILE_HEADER = malstruct.Struct(
    "Machine" / malstruct.Int16ul,  # IMAGE_FILE_MACHINE_*
    "NumberOfSections" / malstruct.Int16ul,
    "TimeDateStamp" / malstruct.Int32ul,
    "PointerToSymbolTable" / malstruct.Default(malstruct.Int32ul, 0),
    "NumberOfSymbols" / malstruct.Default(malstruct.Int32ul, 0),
    # NOTE: This defaults to assuming a 32-bit PE when building if the SizeOfOptionalHeader isn't provided in the context.
    "SizeOfOptionalHeader" / malstruct.Default(
        malstruct.Int16ul, IMAGE_OPTIONAL_HEADER.sizeof(Magic=IMAGE_NT_OPTIONAL_HDR32_MAGIC, NumberOfRvaAndSizes=16)),
    "Characteristics" / malstruct.FlagsEnum(
        malstruct.Int16ul,
        IMAGE_FILE_RELOCS_STRIPPED=0x0001,
        IMAGE_FILE_EXECUTABLE_IMAGE=0x0002,
        IMAGE_FILE_LINE_NUMS_STRIPPED=0x0004,
        IMAGE_FILE_LOCAL_SYMS_STRIPPED=0x0008,
        IMAGE_FILE_AGGRESIVE_WS_TRIM=0x0010,
        IMAGE_FILE_LARGE_ADDRESS_AWARE=0x0020,
        IMAGE_FILE_BYTES_REVERSED_LO=0x0080,
        IMAGE_FILE_32BIT_MACHINE=0x0100,
        IMAGE_FILE_DEBUG_STRIPPED=0x0200,
        IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP=0x0400,
        IMAGE_FILE_NET_RUN_FROM_SWAP=0x0800,
        IMAGE_FILE_SYSTEM=0x1000,
        IMAGE_FILE_DLL=0x2000,
        IMAGE_FILE_UP_SYSTEM_ONLY=0x4000,
        IMAGE_FILE_BYTES_REVERSED_HI=0x8000,
    ),
)

IMAGE_NT_HEADERS = malstruct.Struct(
    "Signature" / malstruct.Default(malstruct.Int32ul, 0x4550),  # b'PE\x00\x00'
    "FileHeader" / IMAGE_FILE_HEADER,
    "OptionalHeader" / IMAGE_OPTIONAL_HEADER
)

PEFILE_HEADER = malstruct.Struct(
    "DosHeader" / IMAGE_DOS_HEADER,
    # TODO: Use malstruct.FixedSized() if we ever update malstruct.
    "DosStub" / malstruct.Bytes(this.DosHeader.e_lfanew - IMAGE_DOS_HEADER.sizeof()),
    "NTHeaders" / IMAGE_NT_HEADERS,
    "SectionTable" / IMAGE_SECTION_HEADER[this.NTHeaders.FileHeader.NumberOfSections],
)

"""WINSOCK STRUCTURES"""

SOCKADDR_IN = malstruct.Struct(
    "sin_family" / malstruct.Int16ul,
    "sin_port" / malstruct.Int16ub,  # in network byte order
    "sin_addr" / network.IP4Address,
    "sin_zero" / malstruct.Bytes(8)
)

# Same as SOCKADDR_IN but with the port as little endian.
SOCKADDR_IN_L = malstruct.Struct(
    "sin_family" / malstruct.Int16ul,
    "sin_port" / malstruct.Int16ul,
    "sin_addr" / network.IP4Address,
    "sin_zero" / malstruct.Bytes(8)
)

"""CRYPTO STRUCTURES"""

PUBLICKEYSTRUC = malstruct.Struct(
    "type" / malstruct.Byte,
    "version" / malstruct.Byte,
    "reserved" / malstruct.Int16ul,
    "algid" / windows_enums.AlgorithmID(malstruct.Int32ul),
)

PUBLICKEYBLOB = malstruct.Struct(
    "publickeystruc" / PUBLICKEYSTRUC,
    malstruct.Check(this.publickeystruc.algid == "CALG_RSA_KEYX"),
    malstruct.Const(b"RSA1"),
    "bitlen" / malstruct.Int32ul,
    malstruct.Check((this.bitlen % 8) == 0),
    "pubexponent" / malstruct.Int32ul,
    "modulus" / malstruct.BytesInteger(this.bitlen // 8, swapped=True)
)

PRIVATEKEYBLOB = malstruct.Struct(
    "publickeystruc" / PUBLICKEYSTRUC,
    malstruct.Check(this.publickeystruc.algid == "CALG_RSA_KEYX"),
    malstruct.Const(b"RSA2"),
    "bitlen" / malstruct.Int32ul,
    malstruct.Check((this.bitlen % 8) == 0),
    "pubexponent" / malstruct.Int32ul,
    "modulus" / malstruct.BytesInteger(this.bitlen // 8, swapped=True),
    "P" / malstruct.BytesInteger(this.bitlen // 16, swapped=True),
    "Q" / malstruct.BytesInteger(this.bitlen // 16, swapped=True),
    # d % (p - 1)
    "Dp" / malstruct.BytesInteger(this.bitlen // 16, swapped=True),
    # d % (q - 1)
    "Dq" / malstruct.BytesInteger(this.bitlen // 16, swapped=True),
    # ~(q % p)
    "Iq" / malstruct.BytesInteger(this.bitlen // 16, swapped=True),
    # Private Exponent
    "D" / malstruct.BytesInteger(this.bitlen // 8, swapped=True)
)

"""TIME STRUCTURES"""

SYSTEMTIME = malstruct.Struct(
    "wYear" / malstruct.Int16ul,
    "wMonth" / malstruct.Int16ul,
    "wDayOfWeek" / malstruct.Int16ul,
    "wDay" / malstruct.Int16ul,
    "wHour" / malstruct.Int16ul,
    "wMinute" / malstruct.Int16ul,
    "wSecond" / malstruct.Int16ul,
    "wMilliseconds" / malstruct.Int16ul,
)


# TODO: Implement _encode
class SystemTimeAdapter(malstruct.Adapter):
    r"""
    Adapter to convert SYSTEMTIME structured data to datetime.datetime ISO format.

    >>> SystemTimeAdapter(SYSTEMTIME).parse(b'\xdd\x07\t\x00\x03\x00\x12\x00\t\x00.\x00\x15\x00\xf2\x02')
    '2013-09-18T09:46:21.754000'
    >>> SystemTimeAdapter(SYSTEMTIME, tzinfo=datetime.timezone.utc).parse(b'\xdd\x07\t\x00\x03\x00\x12\x00\t\x00.\x00\x15\x00\xf2\x02')
    '2013-09-18T09:46:21.754000+00:00'
    """
    def __init__(self, subcon, tzinfo=None):
        """
        :param tzinfo: Optional timezone object, default is localtime
        :param subcon: subcon to parse SystemTime
        """
        super().__init__(subcon)
        self._tzinfo = tzinfo

    def _decode(self, obj, context, path):
        try:
            return datetime.datetime(
                obj.wYear, obj.wMonth, obj.wDay, obj.wHour, obj.wMinute, obj.wSecond, obj.wMilliseconds * 1000,
                tzinfo=self._tzinfo
            ).isoformat()
        except OSError as e:
            raise malstruct.malstructError(e)


# Add common helpers
SystemTime = SystemTimeAdapter(SYSTEMTIME)
SystemTimeUTC = SystemTimeAdapter(SYSTEMTIME, tzinfo=datetime.timezone.utc)


EPOCH_AS_FILETIME = 116444736000000000
HUNDREDS_OF_NANOSECONDS = 10000000


# TODO: Implement _encode
class FileTimeAdapter(malstruct.Adapter):
    r"""
    Adapter to convert FILETIME structured data to datetime.datetime ISO format.
    Technically FILETIME is two 32-bit integers as dwLowDateTime and dwHighDateTime, but there is no need to do that

    >>> FileTimeAdapter(malstruct.Int64ul).parse(b'\x00\x93\xcc\x11\xa7\x88\xd0\x01')
    '2015-05-07T05:20:33.328000'
    >>> FileTimeAdapter(malstruct.Int64ul, tz=datetime.timezone.utc).parse(b'\x00\x93\xcc\x11\xa7\x88\xd0\x01')
    '2015-05-07T09:20:33.328000+00:00'
    """
    def __init__(self, subcon, tz=None):
        """
        :param tz: Optional timezone object, default is localtime
        :param subcon: subcon to parse FileTime
        """
        super().__init__(subcon)
        self._tz = tz

    def _decode(self, obj, context, path):
        try:
            return datetime.datetime.fromtimestamp(
                (obj - EPOCH_AS_FILETIME) / HUNDREDS_OF_NANOSECONDS, tz=self._tz
            ).isoformat()
        except OSError as e:
            raise malstruct.malstructError(e)


# Add common helpers
FileTime = FileTimeAdapter(malstruct.Int64ul)
FileTimeUTC = FileTimeAdapter(malstruct.Int64ul, tz=datetime.timezone.utc)
