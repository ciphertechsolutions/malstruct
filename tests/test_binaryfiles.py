import io
import pathlib

import elftools.elf.elffile as elffile
import pefile
import pytest

from malstruct import (
    Bytes,
    ELFMemoryAddress,
    ELFPointer,
    Int32ul,
    PEAddressFromRVA,
    PEMemoryAddress,
    PEPhysicalAddress,
    PEPointer,
    PEPointer64,
    PERVAPointer,
    Struct,
    Tell,
    this,
)

SAMPLES_PATH = pathlib.Path(__file__).parent / "samples"


def read_file_data(file_path: pathlib.Path) -> bytes | None:
    if file_path.exists():
        return file_path.read_bytes()
    pytest.skip(f"{file_path} does not exist.")


def obtain_pe(data: bytes) -> pefile.PE | None:
    try:
        return pefile.PE(data=data)
    except pefile.PEFormatError:
        pass
    pytest.skip(f"Failed to acquire pefile object.")


def obtain_elf(data: bytes) -> elffile.ELFFile | None:
    try:
        return elffile.ELFFile(io.BytesIO(data))
    except elffile.ELFError:
        pass
    pytest.skip(f"Failed to acquire an elffile object.")


def test_pe32():
    if (data := read_file_data(SAMPLES_PATH / "test32.exe")) and (
        pe := obtain_pe(data)
    ):
        assert PEPhysicalAddress(Int32ul, pe=pe).parse(b"\x000@\x00") == 0x800
        assert PEPhysicalAddress(Int32ul, pe=pe).build(0x800) == b"\x000@\x00"
        assert PEPhysicalAddress(Int32ul).parse(b"\x000@\x00", pe=pe) == 0x800
        assert PEPhysicalAddress(Int32ul).build(0x800, pe=pe) == b"\x000@\x00"

        assert PEMemoryAddress(Int32ul, pe=pe).parse(b"\x00\x08\x00\x00") == 0x403000
        assert PEMemoryAddress(Int32ul, pe=pe).build(0x403000) == b"\x00\x08\x00\x00"
        assert PEMemoryAddress(Int32ul).parse(b"\x00\x08\x00\x00", pe=pe) == 0x403000
        assert PEMemoryAddress(Int32ul).build(0x403000, pe=pe) == b"\x00\x08\x00\x00"

        assert PEAddressFromRVA(Int32ul, pe=pe).parse(b"\x000\x00\x00") == 0x800
        assert PEAddressFromRVA(Int32ul, pe=pe).build(0x800) == b"\x000\x00\x00"
        assert PEAddressFromRVA(Int32ul).parse(b"\x000\x00\x00", pe=pe) == 0x800
        assert PEAddressFromRVA(Int32ul).build(0x800, pe=pe) == b"\x000\x00\x00"

        with io.BytesIO(data) as stream:
            stream.seek(0x416)
            spec = Struct(
                "offset" / Int32ul, "data" / PEPointer(this.offset, Bytes(13))
            )
            assert spec.parse_stream(stream, pe=pe).data == b"Hello, World!"

        assert PERVAPointer(0x3000, Bytes(13)).parse(data, pe=pe) == b"Hello, World!"


def test_pe64():
    if (data := read_file_data(SAMPLES_PATH / "test64.exe")) and (
        pe := obtain_pe(data)
    ):
        with io.BytesIO(data) as stream:
            stream.seek(0x429)
            spec = Struct(
                "relative_offset" / Int32ul,
                "instruction_end" / Tell,
                "data"
                / PEPointer64(this.relative_offset, this.instruction_end, Bytes(13)),
            )
            assert spec.parse_stream(stream, pe=pe).data == b"Hello, World!"

            stream.seek(0x429)
            spec = Struct(
                "relative_offset" / Int32ul,
                "instruction_end" / PEMemoryAddress(Tell),
                "data"
                / PEPointer(this.relative_offset + this.instruction_end, Bytes(13)),
            )
            assert spec.parse_stream(stream, pe=pe).data == b"Hello, World!"


def test_elf():
    if (data := read_file_data(SAMPLES_PATH / "hello.elf")) and (
        elf := obtain_elf(data)
    ):
        assert (
            ELFMemoryAddress(Int32ul, elf=elf).parse(b"\xa4\x00\x00\x00") == 0x80490A4
        )
        assert (
            ELFMemoryAddress(Int32ul, elf=elf).build(0x80490A4) == b"\xa4\x00\x00\x00"
        )
        assert (
            ELFMemoryAddress(Int32ul).parse(b"\xa4\x00\x00\x00", elf=elf) == 0x80490A4
        )
        assert (
            ELFMemoryAddress(Int32ul).build(0x80490A4, elf=elf) == b"\xa4\x00\x00\x00"
        )

        with io.BytesIO(data) as stream:
            stream.seek(0x8B)
            spec = Struct(
                "offset" / Int32ul, "data" / ELFPointer(this.offset, Bytes(13))
            )
            assert spec.parse_stream(stream, elf=elf).data == b"Hello, World!"
