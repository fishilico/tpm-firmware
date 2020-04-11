#!/usr/bin/env python3
"""Extract parts from the firmware update"""
import binascii
import ctypes
import hashlib
import json
from pathlib import Path
import struct
import subprocess
from typing import FrozenSet, List, Optional, Tuple
import uuid
import zlib


BASE_DIR = Path(__file__).parent
UPDATE_FILE = BASE_DIR / 'f7375df3c5f903f55ffd64e9ce891da3aa535355-DellTpm1.2_Fw5.81.2.1.cab'

OFFSET_START_OF_EXE = 0x1000
OFFSET_END_OF_EXE = 0x5a600
FLASH_PAYLOAD_START = OFFSET_END_OF_EXE + 0x200

EXTRACTED_DIR = BASE_DIR / 'extracted'
FIRMWARE_BIN = EXTRACTED_DIR / 'firmware.bin'
UPDATE_EXE = EXTRACTED_DIR / 'update.exe'
FLASH_PAYLOAD_BIN = EXTRACTED_DIR / 'flash_payload.pfs.bin'
SIGNED_MESSAGES_TXT = EXTRACTED_DIR / 'signed_messages.txt'
FLASH_PAYLOAD_MERGED_BIN = EXTRACTED_DIR / 'flash_payload.merged.bin'
FLASH_PAYLOAD_DIGESTS_JSON = EXTRACTED_DIR / 'flash_payload.digests.json'


DRIVER_XOR_KEY = 0xD4C783A6E9AD96B0
DRIVER_32BIT_ADDR = 0x450108
DRIVER_32BIT_SIZE = 0x33f8
DRIVER_64BIT_ADDR = 0x453500
DRIVER_64BIT_SIZE = 0x39f8
IMAGE_BASE = 0x400000
DATA_SECTION_RVA = 0x050000
DATA_SECTION_FILE_OFF = 0x04e800

DRIVER_32BIT_PATH = EXTRACTED_DIR / 'DBUtil_2_3.x86_32.sys'
DRIVER_64BIT_PATH = EXTRACTED_DIR / 'DBUtil_2_3.x86_64.sys'


def xor_checksum(data: bytes) -> int:
    """Checksum with a XOR"""
    result = 0
    for x in data:
        result ^= x
    return result


def xx(data: bytes) -> str:
    return binascii.hexlify(data).decode('ascii')


EXTRACTED_DIR.mkdir(exist_ok=True)

if not FIRMWARE_BIN.exists():
    # print(f"Extracting {FIRMWARE_BIN} into {EXTRACTED_DIR}")
    subprocess.check_call(
        ['7z', 'x', f'../{UPDATE_FILE.name}'],
        cwd=EXTRACTED_DIR)

with FIRMWARE_BIN.open('rb') as stream:
    firmware_data = stream.read()

print(f"File {FIRMWARE_BIN} from {UPDATE_FILE.name!r}")
print(f"[000000..{OFFSET_START_OF_EXE:06x}] UEFI Capsule Header ({OFFSET_START_OF_EXE} bytes)")  # noqa
print(f"[{OFFSET_START_OF_EXE:06x}..{OFFSET_END_OF_EXE:06x}] Windows executable ({OFFSET_END_OF_EXE - OFFSET_START_OF_EXE} bytes)")  # noqa
update_exe_data: bytes = firmware_data[OFFSET_START_OF_EXE:OFFSET_END_OF_EXE]

with UPDATE_EXE.open('wb') as fout:
    fout.write(update_exe_data)


# Extract embedded drivers
def extract_driver(output_path: Path, virtual_addr: int, size: int):
    section_offset = virtual_addr - IMAGE_BASE - DATA_SECTION_RVA
    assert section_offset > 0
    file_offset = DATA_SECTION_FILE_OFF + section_offset
    print(f"  [{file_offset:06x}..{file_offset + size:06x}] obfuscated {output_path.name} ({size} bytes)")  # noqa
    driver_data = bytearray(update_exe_data[file_offset:file_offset + size])
    key = DRIVER_XOR_KEY
    for i in range(size):
        driver_data[i] ^= key & 0xff
        key = ((key << 61) & 0xffffffffffffffff) | (key >> 3)
    with output_path.open('wb') as fout:
        fout.write(driver_data)


extract_driver(DRIVER_32BIT_PATH, DRIVER_32BIT_ADDR, DRIVER_32BIT_SIZE)
extract_driver(DRIVER_64BIT_PATH, DRIVER_64BIT_ADDR, DRIVER_64BIT_SIZE)


# many "FF" between the Windows application and UEFI partition data
assert FLASH_PAYLOAD_START > OFFSET_END_OF_EXE
print(f"[{OFFSET_END_OF_EXE:06x}..{FLASH_PAYLOAD_START:06x}] Padding with 0xff ({FLASH_PAYLOAD_START - OFFSET_END_OF_EXE} bytes)")  # noqa
assert all(x == 0xff for x in firmware_data[OFFSET_END_OF_EXE:FLASH_PAYLOAD_START])

# Parse Flash Payload Marker (with .data:004583C8 and .data:004583D4)
print(f"[{FLASH_PAYLOAD_START:06x}..{len(firmware_data):06x}] Flash payload with markers ({len(firmware_data) - FLASH_PAYLOAD_START} bytes)")  # noqa

part_size: int = struct.unpack('<I', firmware_data[FLASH_PAYLOAD_START:FLASH_PAYLOAD_START + 4])[0]
part_size_eof: int = struct.unpack('<I', firmware_data[-0x10:-0xc])[0]

print(f"  [{FLASH_PAYLOAD_START:06x}..{FLASH_PAYLOAD_START + 0x10:06x}] Flash Payload Start Marker (size {part_size:#x} + 'aaeeaa761becbb20f1e651' + byte for checksum)")  # noqa
print(f"  [{FLASH_PAYLOAD_START + 0x10:06x}..{FLASH_PAYLOAD_START + 0x10 + part_size:06x}] Zlib-compressed Flash Payload ({part_size} bytes)")  # noqa
print(f"  [{len(firmware_data) - 0x10:06x}..{len(firmware_data):06x}] Flash Payload End Marker (size {part_size_eof:#x} + 'eeaaee8f491be8ae143790' + byte for checksum)")  # noqa

assert firmware_data[FLASH_PAYLOAD_START+4:FLASH_PAYLOAD_START+0xf] == binascii.unhexlify(b'aaeeaa761becbb20f1e651')
assert firmware_data[-0xc:-1] == binascii.unhexlify(b'eeaaee8f491be8ae143790')
assert xor_checksum(firmware_data[FLASH_PAYLOAD_START:FLASH_PAYLOAD_START+0x10]) == 0
assert xor_checksum(firmware_data[-0x10:]) == 0
assert part_size == part_size_eof
assert len(firmware_data) == FLASH_PAYLOAD_START + 0x20 + part_size, \
    f"Mismatched size: {len(firmware_data):#x} != {FLASH_PAYLOAD_START:#x} + 0x20 + {part_size:#x} = {FLASH_PAYLOAD_START + 0x20 + part_size:#x}"  # noqa

flash_payload_data: bytes = zlib.decompress(firmware_data[FLASH_PAYLOAD_START + 0x10:-0x10])

with FLASH_PAYLOAD_BIN.open('wb') as fout:
    fout.write(flash_payload_data)

print('')

# The flash payload uses a "Dell PFS" format, and the update program implements a parser named PfsReader
# There are over GUID documented in https://github.com/theopolis/uefi-firmware-parser/blob/master/uefi_firmware/pfs.py:
#    "FIRMWARE_VOLUMES": "7ec6c2b0-3fe3-42a0-a316-22dd0517c1e8"
#    "INTEL_ME":         "7439ed9e-70d3-4b65-9e33-1963a7ad3c37"
#    "BIOS_ROMS_1":      "08e56a30-62ed-41c6-9240-b7455ee653d7"
#    "BIOS_ROMS_2":      "492261e4-0659-424c-82b6-73274389e7a7"
PFS_GUID_MANIFEST = '4d583fd3-f80e-4055-a145-9bec16cb33b0'
PFS_GUID_TPM_1 = '5034bac4-0814-4f53-8050-7e20990d1638'
PFS_GUID_TPM_2 = 'c22d63f4-f182-40fc-b238-e5f89fbf3b87'


class PfsFileHeader(ctypes.LittleEndianStructure):
    MAGIC = b'PFS.HDR.'
    _fields_ = [
        ('Magic', ctypes.c_uint8 * 8),
        ('spec', ctypes.c_uint32),
        ('content_size', ctypes.c_uint32),
    ]

    def __str__(self) -> str:
        return f"PFS header ({bytes(self.Magic)!r}, spec={self.spec}, size={self.content_size})"


assert ctypes.sizeof(PfsFileHeader) == 0x10


class PfsFileFooter(ctypes.LittleEndianStructure):
    MAGIC = b'PFS.FTR.'
    _fields_ = [
        ('content_size', ctypes.c_uint32),
        ('crc', ctypes.c_uint32),
        ('Magic', ctypes.c_uint8 * 8),
    ]

    def __str__(self) -> str:
        return f"PFS footer ({bytes(self.Magic)!r}, size={self.content_size}, CRC={self.crc:#010x})"


assert ctypes.sizeof(PfsFileFooter) == 0x10


def decode_pfs_version(version_spec, version_ints):
    version_parts = []
    for spec, part in zip(version_spec, version_ints):
        if spec == ord('A'):
            version_parts.append(f'{part:X}')
        elif spec == ord('N'):
            version_parts.append(f'{part:d}')
        else:
            raise NotImplementedError(f"Unknown version specification {version_spec} for {version_ints}")
    return '.'.join(version_parts)


class PfsSectionHeader(ctypes.LittleEndianStructure):
    _fields_ = [
        ('raw_guid', ctypes.c_uint8 * 16),
        ('spec', ctypes.c_uint32),
        ('version_spec', ctypes.c_uint8 * 4),
        ('version_ints', ctypes.c_uint16 * 4),
        ('reserved1', ctypes.c_uint32),
        ('reserved2', ctypes.c_uint32),
        ('data_size', ctypes.c_uint32),
        ('rsa1_size', ctypes.c_uint32),
        ('pmim_size', ctypes.c_uint32),
        ('rsa2_size', ctypes.c_uint32),
        ('pmim_crc', ctypes.c_uint32),
        ('rsa2_crc', ctypes.c_uint32),
        ('data_crc', ctypes.c_uint32),
        ('rsa1_crc', ctypes.c_uint32),
    ]

    @property
    def total_size(self) -> int:
        return 0x48 + self.data_size + self.rsa1_size + self.pmim_size + self.rsa2_size

    @property
    def guid(self) -> uuid.UUID:
        return uuid.UUID(bytes_le=bytes(self.raw_guid))

    @property
    def version(self) -> str:
        return decode_pfs_version(self.version_spec, self.version_ints)

    def __str__(self) -> str:
        params = f"GUID={self.guid}, spec={self.spec}, version={self.version}"
        if self.reserved1:
            params += f", reserved1={self.reserved1}"
        if self.reserved2:
            params += f", reserved2={self.reserved2}"
        return f"Section header ({params})"


assert ctypes.sizeof(PfsSectionHeader) == 0x48


def pfs_crc32(data: bytes) -> int:
    """CRC32 used in PFS format"""
    return binascii.crc32(data) ^ 0xffffffff


assert pfs_crc32(b'') == 0xffffffff
assert pfs_crc32(b'\x80') == 0xc0459352

print(f"PFS update (saved in {FLASH_PAYLOAD_BIN}):")
pfs_header: PfsFileHeader = PfsFileHeader.from_buffer_copy(flash_payload_data, 0)
print(f"[{0:06x}..{ctypes.sizeof(pfs_header):06x}] {pfs_header}")
assert bytes(pfs_header.Magic) == PfsFileHeader.MAGIC

# Maintain a list of signatures
signed_messages: List[Tuple[bytes, bytes]] = []

flash_update_manifest_data: Optional[bytes] = None
flash_update_tpm1_data: Optional[bytes] = None
flash_update_tpm2_data: Optional[bytes] = None

section_offset = ctypes.sizeof(pfs_header)
section_offset_limit = section_offset + pfs_header.content_size
while section_offset < section_offset_limit:
    section_header: PfsSectionHeader = PfsSectionHeader.from_buffer_copy(flash_payload_data, section_offset)
    print(f"[{section_offset:06x}..{section_offset + section_header.total_size:06x}] Section ({section_header.total_size} bytes)")  # noqa
    print(f"  [{section_offset:06x}..{section_offset + ctypes.sizeof(section_header):06x}] {section_header}")
    section_offset += ctypes.sizeof(section_header)

    section_data = flash_payload_data[section_offset:section_offset + section_header.data_size]
    if section_header.data_size:
        print(f"  [{section_offset:06x}..{section_offset + section_header.data_size:06x}] Data ({section_header.data_size} bytes, CRC={section_header.data_crc:#010x})")  # noqa
        assert pfs_crc32(section_data) == section_header.data_crc
        section_offset += section_header.data_size

        section_guid = str(section_header.guid)
        if section_guid == PFS_GUID_MANIFEST:
            print("    ... Update Manifest")
            flash_update_manifest_data = section_data
        elif section_guid == PFS_GUID_TPM_1:
            print("    ... TPM 1 Update")
            flash_update_tpm1_data = section_data
        elif section_guid == PFS_GUID_TPM_2:
            print("    ... TPM 2 Update")
            flash_update_tpm2_data = section_data
        else:
            print("    ... Unknown GUID")
    else:
        assert section_header.data_crc == 0xffffffff

    rsa1_data = flash_payload_data[section_offset:section_offset + section_header.rsa1_size]
    if section_header.rsa1_size:
        print(f"  [{section_offset:06x}..{section_offset + section_header.rsa1_size:06x}] RSA 1 ({section_header.rsa1_size} bytes, CRC={section_header.rsa1_crc:#010x})")  # noqa
        assert pfs_crc32(rsa1_data) == section_header.rsa1_crc
        section_offset += section_header.rsa1_size
        signed_messages.append((section_data, rsa1_data))
    else:
        assert section_header.rsa1_crc == 0xffffffff

    pmim_data = flash_payload_data[section_offset:section_offset + section_header.pmim_size]
    if section_header.pmim_size:
        print(f"  [{section_offset:06x}..{section_offset + section_header.pmim_size:06x}] PMIM (?) ({section_header.pmim_size} bytes, CRC={section_header.pmim_crc:#010x})")  # noqa
        assert pfs_crc32(pmim_data) == section_header.pmim_crc
        section_offset += section_header.pmim_size
    else:
        assert section_header.pmim_crc == 0xffffffff

    rsa2_data = flash_payload_data[section_offset:section_offset + section_header.rsa2_size]
    if section_header.rsa2_size:
        print(f"  [{section_offset:06x}..{section_offset + section_header.rsa2_size:06x}] RSA 2 (?) ({section_header.rsa2_size} bytes, CRC={section_header.rsa2_crc:#010x})")  # noqa
        assert pfs_crc32(rsa2_data) == section_header.rsa2_crc
        section_offset += section_header.rsa2_size
    else:
        assert section_header.rsa2_crc == 0xffffffff

assert section_offset == section_offset_limit
pfs_footer: PfsFileFooter = PfsFileFooter.from_buffer_copy(flash_payload_data, section_offset_limit)
print(f"[{section_offset_limit:06x}..{section_offset_limit + ctypes.sizeof(pfs_footer):06x}] {pfs_footer}")
assert bytes(pfs_footer.Magic) == PfsFileFooter.MAGIC
assert pfs_footer.content_size == pfs_header.content_size
assert pfs_crc32(flash_payload_data[ctypes.sizeof(pfs_header):section_offset_limit]) == pfs_footer.crc
assert section_offset_limit + ctypes.sizeof(pfs_footer) == len(flash_payload_data)


# Record the signed messages to try getting the public key with
# https://github.com/fishilico/shared/blob/master/python/crypto/find_rsa_pkcs1v15_modulus.py
with SIGNED_MESSAGES_TXT.open('w') as fmsg:
    for msg, signature in signed_messages:
        fmsg.write(f"SHA1 {xx(msg)} {xx(signature)}\n")


if flash_update_manifest_data:
    # Decode the manifest
    print('')
    print("PFS manifest:")
    manifest_spec = struct.unpack('<I', flash_update_manifest_data[:4])[0]
    manifest_guid = uuid.UUID(bytes_le=flash_update_manifest_data[4:0x14])
    manifest_version_ints = struct.unpack('<4H', flash_update_manifest_data[0x14:0x1c])
    manifest_version_spec = struct.unpack('<4B', flash_update_manifest_data[0x1c:0x20])
    manifest_version = decode_pfs_version(manifest_version_spec, manifest_version_ints)
    manifest_desc_len = struct.unpack('<H', flash_update_manifest_data[0x20:0x22])[0]
    manifest_desc = flash_update_manifest_data[0x22:0x22 + 2 * manifest_desc_len].decode('utf-16le')
    manifest_padding = flash_update_manifest_data[0x22 + 2 * manifest_desc_len:]
    print(f"* spec = {manifest_spec}")
    print(f"* data GUID = {manifest_guid}")
    print(f"* version = {manifest_version}")
    print(f"* description = {manifest_desc!r}")
    assert manifest_padding == b'\0\0'

if FLASH_PAYLOAD_DIGESTS_JSON.exists():
    with FLASH_PAYLOAD_DIGESTS_JSON.open('r') as fjson:
        flash_payload_digests: FrozenSet[str] = frozenset(json.load(fjson))
else:
    flash_payload_digests = frozenset()


def try_match_data_with_digests(data: bytes):
    """Try to match the give data with the known digests

    As the digest algorithm is not known, this should always fail
    """
    for trying_digest in ('md4', 'md5', 'sha1', 'sha256'):
        digest = hashlib.new(trying_digest, data).digest()
        assert xx(digest[:0x10]) not in flash_payload_digests, "Found!"
        assert xx(digest[0x10:]) not in flash_payload_digests, "Found!"
        digest = hashlib.new(trying_digest, digest).digest()
        assert xx(digest[:0x10]) not in flash_payload_digests, "Found!"
        assert xx(digest[0x10:]) not in flash_payload_digests, "Found!"
        digest = hashlib.new(trying_digest, digest).digest()
        assert xx(digest[:0x10]) not in flash_payload_digests, "Found!"
        assert xx(digest[0x10:]) not in flash_payload_digests, "Found!"
        digest = hashlib.new(trying_digest, digest).digest()
        assert xx(digest[:0x10]) not in flash_payload_digests, "Found!"
        assert xx(digest[0x10:]) not in flash_payload_digests, "Found!"


if flash_update_tpm1_data:
    # Decode the command packets in the data which is transmitted.
    # Each packet is a TPM 1.2 command, with a structure available for example on
    # https://github.com/tianocore/edk2/blob/edk2-stable202002/MdePkg/Include/IndustryStandard/Tpm12.h
    #     typedef struct tdTPM_RQU_COMMAND_HDR {
    #         TPM_STRUCTURE_TAG tag; // UINT16
    #         UINT32            paramSize;
    #         TPM_COMMAND_CODE  ordinal; // UINT32
    #     } TPM_RQU_COMMAND_HDR;
    #
    # Request commands use this tag:
    #     #define TPM_TAG_RQU_COMMAND ((TPM_STRUCTURE_TAG) 0x00C1)
    #
    # Command ordinals are described in section 17 of
    # https://trustedcomputinggroup.org/wp-content/uploads/TPM-Main-Part-2-TPM-Structures_v1.2_rev116_01032011.pdf
    # They are 32-bit values:
    #    bits 0-15: Command Ordinal Index
    #    bits 16-23: Purview (0x00 for TPM_MAIN, Command is from the main specification)
    #    bits 24-28: Reserved
    #    bit 29: TPM/Vendor command (TPM_VENDOR_COMMAND = 0x20000000)
    #    bit 30: Non-Connection/Connection related command (TPM_CONNECTION_COMMAND = 0x40000000)
    #    bit 31: Protected/Unprotected command (TPM_UNPROTECTED_COMMAND = 0x80000000)
    print('')
    print("TPM 1 Update:")
    tpm_req_offset = 0
    all_data_blocks: List[bytes] = []
    all_data_blocks_by_offset: List[List[bytes]] = [[] for _ in range(11)]
    all_data_hexdigests: List[str] = []
    while tpm_req_offset < len(flash_update_tpm1_data):
        tpm_req_tag, tpm_req_size, tpm_req_ordinal = \
            struct.unpack('>HII', flash_update_tpm1_data[tpm_req_offset:tpm_req_offset + 0xa])
        print(f"[{tpm_req_offset:06x}..{tpm_req_offset + tpm_req_size:06x}] TPM request: tag={tpm_req_tag:#x}, ord={tpm_req_ordinal:#x}, {tpm_req_size} bytes")  # noqa
        assert tpm_req_size >= 0xa
        assert tpm_req_offset + tpm_req_size <= len(flash_update_tpm1_data)
        tpm_req_data = flash_update_tpm1_data[tpm_req_offset + 0xa:tpm_req_offset + tpm_req_size]

        # All commands are Vendor commands
        assert tpm_req_ordinal & 0xffff0000 == 0x20000000

        if tpm_req_tag == 0x8001:
            # Unknown reserved tag (upper nibble 8)
            # Only the first request is like this
            assert tpm_req_offset == 0

            # So far, only ordinal 0x20000200 has been seen
            assert tpm_req_ordinal == 0x20000200

            cur_offset = 0

            # There are 2 sub-blocks
            blk1_size = struct.unpack('>I', tpm_req_data[cur_offset:cur_offset + 4])[0]
            assert blk1_size == 0x2a
            blk1_data = struct.unpack('>21H', tpm_req_data[cur_offset + 4:cur_offset + 4 + blk1_size])
            # Group by 3 integers (42 = 7 * 6 bytes)
            blk1_data_hex = " ".join(
                f"{blk1_data[idx]:04x}-{blk1_data[idx + 1]:04x}-{blk1_data[idx + 2]:04x}"
                for idx in range(0, 21, 3))
            print(f"  [{cur_offset:04x}..{cur_offset + 4 + blk1_size:04x}] sub-block ({blk1_size} bytes): {blk1_data_hex}")  # noqa
            cur_offset += blk1_size + 4

            blk2_size = struct.unpack('>I', tpm_req_data[cur_offset:cur_offset + 4])[0]
            blk2_blob = tpm_req_data[cur_offset + 4:cur_offset + 4 + blk2_size]
            print(f"  [{cur_offset:04x}..{cur_offset + blk2_size + 4:04x}] sub-block ({blk2_size} bytes): {xx(blk2_blob)}")  # noqa
            cur_offset += blk2_size + 4
            assert cur_offset == len(tpm_req_data)

            # Go to next block
            tpm_req_offset += tpm_req_size
            continue

        # Otherwise, the tag is always TPM_TAG_RQU_COMMAND = 0x00c1
        assert tpm_req_tag == 0x00c1

        if tpm_req_ordinal == 0x20000035:
            # 2nd and 3rd requests, 8-byte long.
            # Probably commands to put the TPM in "field upgrade mode"?
            # Or memory regions? This look like intervals
            assert len(tpm_req_data) == 8
            addr_start, addr_end = struct.unpack('>2I', tpm_req_data)
            range_size = addr_end - addr_start + 1
            print(f"  [{0:04x}..{8:04x}] interval: {addr_start:#x}..{addr_end:#x} ({range_size}={range_size:#x} bytes)")  # noqa
            tpm_req_offset += tpm_req_size
            continue

        if tpm_req_ordinal == 0x20000033:
            # Requests with data chunks
            # There are 2 sub-blocks: 0x1c bytes with what look like a hash,
            # and a block containing some data
            # Data chunks
            blk1_size = struct.unpack('>I', tpm_req_data[:4])[0]
            assert blk1_size == 0x1c
            blk1_ints = struct.unpack('>3I', tpm_req_data[4:0x10])
            blk1_blob = tpm_req_data[0x10:0x20]
            print(f"  [{0:04x}..{0x20:04x}] digest or IV ({blk1_size} bytes): {blk1_ints[0]:#x}, {blk1_ints[1]:#x}, {blk1_ints[2]:#x}, {xx(blk1_blob)}")  # noqa
            assert blk1_ints == (0x10, 0x10, 0x10)

            data_size = struct.unpack('>I', tpm_req_data[0x20:0x24])[0]
            sub_data = tpm_req_data[0x24:0x24 + data_size]
            print(f"  [{0x20:04x}..{0x24 + data_size:04x}] data ({data_size} bytes): {xx(sub_data[:0x20])}...{xx(sub_data[-0x20:])}")  # noqa

            all_data_hexdigests.append(xx(blk1_blob))
            all_data_blocks.append(sub_data)

            # Try several data chunks and digests, in case someday one of them work
            try_match_data_with_digests(sub_data)
            try_match_data_with_digests(tpm_req_data[0x20:])
            try_match_data_with_digests(tpm_req_data)
            try_match_data_with_digests(flash_update_tpm1_data[tpm_req_offset:tpm_req_offset + tpm_req_size])
            try_match_data_with_digests(b''.join(all_data_blocks))

            # Try to consider all bytes but 10, in order for the total size to sum up nicely
            for chunk_offset in range(11):
                offseted_sub_data = sub_data[chunk_offset:len(sub_data) - 10 + chunk_offset]
                all_data_blocks_by_offset[chunk_offset].append(offseted_sub_data)
                try_match_data_with_digests(offseted_sub_data)
                try_match_data_with_digests(b''.join(all_data_blocks_by_offset[chunk_offset]))

            assert 0x24 + data_size == len(tpm_req_data)
            tpm_req_offset += tpm_req_size
            continue

        if tpm_req_ordinal == 0x20000034:
            # Last request, with information related to the firmware
            version_ints = struct.unpack('6B', tpm_req_data[:6])
            print(f"  [{0:04x}..{2:04x}] TPM version {version_ints[0]}.{version_ints[1]}")
            print(f"  [{2:04x}..{6:04x}] FW version {version_ints[2]}.{version_ints[3]}.{version_ints[4]}.{version_ints[5]}")  # noqa

            blk1_size = struct.unpack('>I', tpm_req_data[6:0xa])[0]
            assert blk1_size == 0x1c
            blk1_ints = struct.unpack('>3I', tpm_req_data[0xa:0x16])
            blk1_blob = tpm_req_data[0x16:0x26]
            print(f"  [{6:04x}..{0x26:04x}] digest or IV ({blk1_size} bytes): {blk1_ints[0]:#x}, {blk1_ints[1]:#x}, {blk1_ints[2]:#x}, {xx(blk1_blob)}")  # noqa
            assert blk1_ints == (0x10, 0x10, 0x10)
            all_data_hexdigests.append(xx(blk1_blob))

            blk2_size = struct.unpack('>I', tpm_req_data[0x26:0x2a])[0]
            assert blk2_size == 0x10
            blk2_blob = tpm_req_data[0x2a:0x3a]
            print(f"  [{0x26:04x}..{0x3a:04x}] probably digest ({blk2_size} bytes): {xx(blk2_blob)}")
            all_data_hexdigests.append(xx(blk2_blob))

            blk3_size = struct.unpack('>I', tpm_req_data[0x3a:0x3e])[0]
            assert blk3_size == 0x100
            blk3_blob = tpm_req_data[0x3e:0x13e]
            print(f"  [{0x3a:04x}..{0x13e:04x}] sub-block ({blk3_size} bytes): {xx(blk3_blob)}")
            assert 0x13e == len(tpm_req_data)
            tpm_req_offset += tpm_req_size
            continue

        # Unknown request
        print(f" ??? {xx(tpm_req_data)}")
        tpm_req_offset += tpm_req_size

    # Ensure that all TPM requests were consumed
    assert tpm_req_offset == len(flash_update_tpm1_data)

all_data_size = sum(len(b) for b in all_data_blocks)
print(f"Extracted {len(all_data_blocks)} chunks, {all_data_size}={all_data_size:#x} bytes total, in {FLASH_PAYLOAD_MERGED_BIN}")  # noqa

# Save the concatenation of all data chunk
with FLASH_PAYLOAD_MERGED_BIN.open('wb') as fout:
    fout.write(b''.join(all_data_blocks))

for chunk_offset in range(11):
    all_data_size = sum(len(b) for b in all_data_blocks_by_offset[chunk_offset])
    offseted_out_file = EXTRACTED_DIR / f'flash_payload.merged_{chunk_offset:02d}.bin'
    print(f"  [offset {chunk_offset:02d}/10] extracted {all_data_size}={all_data_size:#x} bytes in {offseted_out_file}")  # noqa
    with offseted_out_file.open('wb') as fout:
        fout.write(b''.join(all_data_blocks_by_offset[chunk_offset]))

# Save all digests, in order to find out what they match
with FLASH_PAYLOAD_DIGESTS_JSON.open('w') as fjson:
    json.dump(all_data_hexdigests, fjson, indent=2)
    fjson.write('\n')
