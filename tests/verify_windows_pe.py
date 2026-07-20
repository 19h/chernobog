#!/usr/bin/env python3
"""Verify architecture and ABI-sensitive imports of a Windows plugin PE."""

import argparse
import struct
import sys
from pathlib import Path


MACHINES = {
    "amd64": 0x8664,
    "arm64": 0xAA64,
}


class PEError(ValueError):
    pass


def unpack_from(fmt, image, offset):
    size = struct.calcsize(fmt)
    if offset < 0 or offset + size > len(image):
        raise PEError("truncated PE structure at file offset 0x%X" % offset)
    return struct.unpack_from(fmt, image, offset)


def c_string(image, offset):
    if offset < 0 or offset >= len(image):
        raise PEError("string offset 0x%X is outside the file" % offset)
    end = image.find(b"\0", offset)
    if end < 0:
        raise PEError("unterminated string at file offset 0x%X" % offset)
    try:
        return image[offset:end].decode("ascii")
    except UnicodeDecodeError as error:
        raise PEError("non-ASCII PE name at file offset 0x%X" % offset) from error


class PEImage:
    def __init__(self, path):
        self.path = Path(path)
        self.image = self.path.read_bytes()
        if len(self.image) < 0x40 or self.image[:2] != b"MZ":
            raise PEError("missing DOS header")

        self.pe_offset = unpack_from("<I", self.image, 0x3C)[0]
        if self.image[self.pe_offset:self.pe_offset + 4] != b"PE\0\0":
            raise PEError("missing PE signature")

        coff = self.pe_offset + 4
        self.machine, self.section_count = unpack_from("<HH", self.image, coff)
        self.optional_size = unpack_from("<H", self.image, coff + 16)[0]
        self.optional_offset = coff + 20
        magic = unpack_from("<H", self.image, self.optional_offset)[0]
        if magic == 0x20B:
            self.thunk_size = 8
            self.ordinal_mask = 1 << 63
            directory_offset = self.optional_offset + 112
            directory_count_offset = self.optional_offset + 108
        elif magic == 0x10B:
            self.thunk_size = 4
            self.ordinal_mask = 1 << 31
            directory_offset = self.optional_offset + 96
            directory_count_offset = self.optional_offset + 92
        else:
            raise PEError("unsupported optional-header magic 0x%X" % magic)

        directory_count = unpack_from(
            "<I", self.image, directory_count_offset)[0]
        if directory_count < 2:
            raise PEError("PE has no import directory")
        self.export_rva, self.export_size = unpack_from(
            "<II", self.image, directory_offset)
        self.import_rva, self.import_size = unpack_from(
            "<II", self.image, directory_offset + 8)
        self.size_of_headers = unpack_from(
            "<I", self.image, self.optional_offset + 60)[0]

        section_offset = self.optional_offset + self.optional_size
        self.sections = []
        for index in range(self.section_count):
            current = section_offset + index * 40
            virtual_size, virtual_address, raw_size, raw_offset = unpack_from(
                "<IIII", self.image, current + 8)
            self.sections.append(
                (virtual_address, max(virtual_size, raw_size), raw_offset, raw_size)
            )

    def rva_offset(self, rva):
        if rva < self.size_of_headers:
            return rva
        for virtual_address, span, raw_offset, raw_size in self.sections:
            if virtual_address <= rva < virtual_address + span:
                delta = rva - virtual_address
                if delta >= raw_size:
                    raise PEError("RVA 0x%X lies outside section raw data" % rva)
                return raw_offset + delta
        raise PEError("RVA 0x%X is not mapped by a section" % rva)

    def imports(self):
        result = set()
        if self.import_rva == 0:
            return result
        descriptor = self.rva_offset(self.import_rva)
        while True:
            original_thunk, timestamp, forwarder, name_rva, first_thunk = unpack_from(
                "<IIIII", self.image, descriptor)
            if not any((original_thunk, timestamp, forwarder, name_rva, first_thunk)):
                break
            dll = c_string(self.image, self.rva_offset(name_rva)).lower()
            thunk_rva = original_thunk or first_thunk
            thunk = self.rva_offset(thunk_rva)
            index = 0
            while True:
                fmt = "<Q" if self.thunk_size == 8 else "<I"
                value = unpack_from(fmt, self.image, thunk + index * self.thunk_size)[0]
                if value == 0:
                    break
                if value & self.ordinal_mask:
                    symbol = "#%d" % (value & 0xFFFF)
                else:
                    hint_name = self.rva_offset(value)
                    symbol = c_string(self.image, hint_name + 2)
                result.add((dll, symbol))
                index += 1
            descriptor += 20
        return result

    def exports(self):
        result = set()
        if self.export_rva == 0:
            return result
        directory = self.rva_offset(self.export_rva)
        name_count = unpack_from("<I", self.image, directory + 24)[0]
        names_rva = unpack_from("<I", self.image, directory + 32)[0]
        names = self.rva_offset(names_rva)
        for index in range(name_count):
            name_rva = unpack_from("<I", self.image, names + index * 4)[0]
            result.add(c_string(self.image, self.rva_offset(name_rva)))
        return result


def import_spec(value):
    if "!" not in value:
        raise argparse.ArgumentTypeError("import must use DLL!symbol syntax")
    dll, symbol = value.split("!", 1)
    if not dll or not symbol:
        raise argparse.ArgumentTypeError("import must use DLL!symbol syntax")
    return dll.lower(), symbol


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("image", type=Path)
    parser.add_argument("--machine", choices=sorted(MACHINES), required=True)
    parser.add_argument("--require-import", action="append", type=import_spec,
                        default=[])
    parser.add_argument("--forbid-import", action="append", type=import_spec,
                        default=[])
    parser.add_argument("--require-export", action="append", default=[])
    arguments = parser.parse_args()

    try:
        pe = PEImage(arguments.image)
        imports = pe.imports()
        exports = pe.exports()
    except (OSError, PEError) as error:
        print("PE verification failed: %s" % error, file=sys.stderr)
        return 1

    expected_machine = MACHINES[arguments.machine]
    failures = []
    if pe.machine != expected_machine:
        failures.append(
            "machine 0x%04X, expected %s (0x%04X)"
            % (pe.machine, arguments.machine, expected_machine)
        )
    for required in arguments.require_import:
        if required not in imports:
            failures.append("missing import %s!%s" % required)
    for forbidden in arguments.forbid_import:
        if forbidden in imports:
            failures.append("forbidden import %s!%s" % forbidden)
    for required in arguments.require_export:
        if required not in exports:
            failures.append("missing export %s" % required)

    if failures:
        for failure in failures:
            print("PE verification failed: %s" % failure, file=sys.stderr)
        return 1

    print(
        "PE verification passed: machine=%s imports=%d exports=%d image=%s"
        % (arguments.machine, len(imports), len(exports), arguments.image)
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
