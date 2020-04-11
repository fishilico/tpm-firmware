Analysis of the update of Dell TPM 1.2 firmware update 5.81.2.1
===============================================================

Initial files
-------------

The update is available on https://fwupd.org/lvfs/devices/com.dell.uefi5034bac4.firmware

* Dell Inc. TPM 1.2 Version 5.81.2.1:
* Uploaded 2017-03-03 22:03:11+00:00
* State stable
* Urgency low
* License proprietary
* Filename ``DellTpm1.2_Fw5.81.2.1.cab``
* Description Initial release

Archive content::

    $ 7z l f7375df3c5f903f55ffd64e9ce891da3aa535355-DellTpm1.2_Fw5.81.2.1.cab
    2017-03-03 17:03:10 ....A         3731               firmware.metainfo.xml
    2017-03-03 17:03:10 ....A       554912               firmware.bin
    2017-03-03 17:03:10 ....A          490               firmware.bin.asc

The metadata file contains ``<release timestamp="1480714375" version="0x5510201">`` (timestamp 2016-12-02 21:32:55 UTC).
There are also many GUIDs used to match the devices where the update applies.
These GUIDs are in a format specific to ``fwupd`` and are basically a truncated SHA1 hash of a string built from the SKU of a system and the TPM version.
For example the first GUID, ``2dddcf05-47bd-53be-9bd6-8633c162b8c5``, matches a Dell Latitude D620 (SKU 06F2) with a TPM 1.2 device because::

    $ python -c 'import uuid;print(uuid.uuid5(uuid.NAMESPACE_DNS, "06f2-1.2"))'
    2dddcf05-47bd-53be-9bd6-8633c162b8c5

Script `<recover_firmware_device_guids.py>`_ displays all the SKU of Dell devices that are targeted by the update.

The signature is a GPG signature created on 2017-03-03 22:03:10 UTC with RSA-2048 key ID 48A6D80E4538BAC2 (Linux Vendor Firmware Service <sign@fwupd.org>, fingerprint ``3FC6 B804 410E D084 0D8F  2F97 48A6 D80E 4538 BAC2``).

The metadata can be obtained using ``fwupgmgr get-details`` too::

    $ fwupdmgr get-details f7375df3c5f903f55ffd64e9ce891da3aa535355-DellTpm1.2_Fw5.81.2.1.cab
    [...]
    └─Unknown Device:
      │   Description:         Updating the system firmware improves performance.
      │   [...]
      └─TPM 1.2 Update:
            New version:       0x5510201
            Remote ID:         lvfs
            Summary:           Firmware for the Dell TPM 1.2
            Licence:           Proprietary
            Size:              554.9 kB
            Vendor:            Dell Inc.
            Flags:             trusted-payload

The ``trusted-payload`` flag means that ``fwupdmgr`` successfully verified the GPG signature of the firmware (detached in ``firmware.bin.asc``).

The firmware itself starts with a header (which is a capsule header) followed by a DOS+PE executable file at offset ``0x1000``::

    00000000: 0000 0000 0000 0000 0000 0000 0000 0000  ................
              ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^---- GUID, empty
    00000010: 0010 0000 0000 0700 a077 0800 0000 0000  .........w......
              ^^^^^^^^^--------------------- header size: 0x1000
                        ^^^^^^^^^----------- flags: 0x70000
                                                CAPSULE_FLAGS_PERSIST_ACROSS_RESET = 0x00010000
                                                CAPSULE_FLAGS_POPULATE_SYSTEM_TABLE = 0x00020000
                                                CAPSULE_FLAGS_INITIATE_RESET = 0x00040000
                                  ^^^^^^^^^- file size: 0x877a0
    00000020: 0000 0000 0000 0000 0000 0000 0000 0000  ................
    *
    00001000: 4d5a b801 4d01 6607 e001 0204 ffff bd27  MZ..M.f........'
    00001010: 0040 0000 ca03 a501 4000 0000 0100 0000  .@......@.......
    00001020: 0100 0000 0000 0000 0000 0000 0000 0000  ................
    00001030: 0000 0000 0000 0000 0000 0000 409a 0200  ............@...
    00001040: 8a03 9e10 0e03 9e10 8902 9e10 7302 9e10  ............s...
    00001050: 5102 9e10 2f02 9e10 1902 9e10 f701 9e10  Q.../...........
    00001060: d501 9e10 ac01 9e10 8a01 9e10 6901 9e10  ............i...
    00001070: 3b01 9e10 f900 9e10 d000 9e10 ba00 9e10  ;...............
    00001080: 5e00 9e10 4800 9e10 2800 9e10 1800 9e10  ^...H...(.......
    00001090: 0900 9e10 ec03 9e10 2804 9e10 7404 9e10  ........(...t...
    000010a0: 6204 9e10 4d04 9e10 c804 9e10 ef04 9e10  b...M...........

    $ file 1000.exe
    1000.exe: PE32 executable (GUI) Intel 80386, for MS Windows

The capsule header is documented in ``fwupd``'s firmware packager: https://github.com/fwupd/fwupd/tree/1.3.9/contrib/firmware_packager
The content of the PE file is described more thoroughly in `<windows_executable.rst>`_.

In binwalk, the firmware file holds "Zlib compressed data, default compression" at offset ``0x5a810``::

    0005a7f0: ffff ffff ffff ffff ffff ffff ffff ffff  ................
    0005a800: 80cf 0200 aaee aa76 1bec bb20 f1e6 51ff  .......v... ..Q.
    0005a810: 789c 74d8 5390 284b b420 d0b6 6ddb 364f  x.t.S.(K. ..m.6O
    0005a820: dbb6 6ddb b66d dbb6 add3 b66d dbee 9e7b  ..m..m.....m...{
    0005a830: df9b 8998 9fbb 2332 23f7 ceac faa8 8895  ......#2#.......

The compressed data is between 16-bytes markers (aligned on 16 bytes) that are checked in the executable::

    0005a800: 80cf 0200 aaee aa76 1bec bb20 f1e6 51ff
              ^^^^^^^^^--------------------------------- size of the Flash Payload
                        ^^^^^^^^^^^^^^^^^^^^^^^^^^^----- Start marker
                                                   ^^--- Checksum (the XOR of the 16 bytes is 0)
    [Zlib-compressed content]
    00087790: 80cf 0200 eeaa ee8f 491b e8ae 1437 90cf
              ^^^^^^^^^--------------------------------- size of the Flash Payload
                        ^^^^^^^^^^^^^^^^^^^^^^^^^^^----- End marker
                                                   ^^--- Checksum (the XOR of the 16 bytes is 0)
    [End of file]

The decompressed data contains some kind of header and footer::

    00000000: 5046 532e 4844 522e 0100 0000 82e0 0200  PFS.HDR.........
        File header:
            "PFS.HDR.": magic
            0100 0000: spec = 1
            82e0 0200: size without header/footer = 0x2e082
    00000010: c4ba 3450 1408 534f 8050 7e20 990d 1638  ..4P..SO.P~ ...8
        Section header:
            GUID = 5034bac4-0814-4f53-8050-7e20990d1638 (content for TPM 1.2)
            (TPM 2.0 would have been c22d63f4-f182-40fc-b238-e5f89fbf3b87)
    00000020: 0100 0000 4e4e 4e4e 0500 5100 0200 0100  ....NNNN..Q.....
            spec = 1
            version = NNNN : 5.81.2.1
    00000030: 0000 0000 0000 0000 c0dd 0200 0001 0000  ................
            unknown = 0
            unknown = 0
            section_size = 0x2ddc0
            rsa1_size = 0x100
    00000040: 0000 0000 0000 0000 ffff ffff ffff ffff  ................
            pmim_size = 0
            rsa2_size = 0
            crc_pmim = -1
            crc_rsa2 = -1
    00000050: bfed 1c1a 3393 adbb 8001 0000 013c 2000  ....3........< .
            crc_section_data = 0x1a1cedbf
            crc_rsa1 = 0xbbad9333
        Section Data: from 0x58 to 0x2de18
        RSA Data: from 0x2de18 to 0x2df18
    00000060: 0200 0000 002a 0044 0102 0551 0201 0000  .....*.D...Q....
    00000070: 001e 0102 054f 0000 0102 0551 0000 0102  .....O.....Q....
    00000080: 0551 0100 0200 0103 0001 0200 0103 0100  .Q..............
    00000090: 0000 0100 dd2c f166 6a06 cc22 66ac bb4f  .....,.fj.."f..O
    ...
    0002df10: c7f3 e5a1 371a 9e5f d33f 584d 0ef8 5540  ....7.._.?XM..U@
        Section header @0x2df18:
            GUID = 4d583fd3-f80e-4055-a145-9bec16cb33b0 (manifest)
    0002df20: a145 9bec 16cb 33b0 0100 0000 4e4e 4e4e  .E....3.....NNNN
            spec = 1
            version = NNNN : 1.0.0.0
    0002df30: 0100 0000 0000 0000 0000 0000 0000 0000  ................
            unknown = 0
            unknown = 0
    0002df40: 3200 0000 0001 0000 0000 0000 0000 0000  2...............
            section_size = 0x32
            rsa1_size = 0x100
            pmim_size = 0
            rsa2_size = 0
    0002df50: ffff ffff ffff ffff 9392 b8f8 f9ff 91ee  ................
            crc_pmim = -1
            crc_rsa2 = -1
            crc_section_data = 0xf8b89293
            crc_rsa1 = 0xee91fff9
        Section data: from 0x2df60 to 0x2df92
        RSA Data: from 0x2df92 to 0x2e092
    0002df60: 0100 0000 c4ba 3450 1408 534f 8050 7e20  ......4P..SO.P~ 
    0002df70: 990d 1638 0500 5100 0200 0100 4e4e 4e4e  ...8..Q.....NNNN
    0002df80: 0700 5400 5000 4d00 2000 3100 2e00 3200  ..T.P.M. .1...2.
    0002df90: 0000 78c5 cf16 462f 7dcb 078a 909c 6a42  ..x...F/}.....jB
        Manifest :
            0100 0000
            c4ba 3450 1408 534f 8050 7e20 990d 1638 :
                GUID = 5034bac4-0814-4f53-8050-7e20990d1638 (content for TPM 1.2)
            0500 5100 0200 0100 : version 5.81.2.1
            4e4e 4e4e : version spec = NNNN
            0700 5400 5000 4d00 2000 3100 2e00 3200 0000 : string "TPM 1.2"
    0002dfa0: df4d 1e58 a4a8 f185 ec19 df21 1aa4 8420  .M.X.......!... 
    0002dfb0: 185e e131 42e6 e61f 4fb0 11f4 7975 2166  .^.1B...O...yu!f
    0002dfc0: dc53 5e02 e42c 5a44 e4d2 3989 1f42 134f  .S^..,ZD..9..B.O
    0002dfd0: fcdb e892 8fe7 438f dcac 9608 c894 68a4  ......C.......h.
    0002dfe0: c414 eae7 3bdd 8f18 0939 1f09 198b 0310  ....;....9......
    0002dff0: 27dd 3f9f b27c d0bb de96 055a a2d0 e5b8  '.?..|.....Z....
    0002e000: 2622 c495 c656 48a2 fb2e 092f ec87 46b0  &"...VH..../..F.
    0002e010: d110 682c 0edf f1fa 2671 04cb af33 901f  ..h,....&q...3..
    0002e020: 1a82 0d99 8233 4a00 2ad5 7783 728f f8cd  .....3J.*.w.r...
    0002e030: 7970 80a2 c759 f853 a178 f7ef 11f2 058f  yp...Y.S.x......
    0002e040: 563c 43fe 89b9 79bb e28e 906a cf2c 0fbe  V<C...y....j.,..
    0002e050: 81c9 8892 e99c 6c6d a01d 39a5 10be 12c1  ......lm..9.....
    0002e060: d485 55d7 b51c ad6f e8ca 635f cab8 61c8  ..U....o..c_..a.
    0002e070: 4ba0 8985 7c76 51d4 fd87 7663 f271 9d75  K...|vQ...vc.q.u
    0002e080: 6be6 acfb 00d5 406f 9ffb 307f a207 228c  k.....@o..0...".
    0002e090: ffab 82e0 0200 3156 7c9a 5046 532e 4654  ......1V|.PFS.FT
    0002e0a0: 522e                                     R.
        File footer @0002e092:
            82e0 0200: size without header/footer = 0x2e082
            3156 7c9a: CRC-32 of the data (polynom 0xedb88320, right-shifted)
            "PFS.FTR.": magic

It is a Dell UEFI partition in PFS format, according to https://github.com/theopolis/uefi-firmware-parser/blob/master/uefi_firmware/pfs.py::

    DellPFS: spec 0x1 size 0x2e082 (188546 bytes)
      Dell PFSSection: 5034bac4-0814-4f53-8050-7e20990d1638 spec 0x01 version '5.81.2.1' size 0x2df08 (188168 bytes)
        RawObject: size= 187840
      Dell PFSSection: 4d583fd3-f80e-4055-a145-9bec16cb33b0 spec 0x01 version '1.0.0.0' size 0x17a (378 bytes)
        RawObject: size= 50
    RawObject: size= 32

The first PFS section holds the firmware update itself while the second one (50 bytes) is a manifest.

`<extract_firmware.py>_` extracts all parts of the ``.cab`` file to make them more understandable.


TPM update
----------

The TPM update (embedded in PFS section ``5034bac4-0814-4f53-8050-7e20990d1638``) is a sequence of TPM requests.
According to TCG specifications, a TPM request starts with a 10-byte header:

* ``Tag`` (16-bit integer, Big Endian), usually ``0x00c1`` for ``TPM_TAG_RQU_COMMAND`` (command request)
* ``Size`` (32-bit integer, Big Endian), the size of the request
* ``Ordinal`` (16-bit integer, Big Endian), the command code of the request

The TCG specification for TPM 1.2 (TPM Main Part 3 Commands Specification Version 1.2 Level 2 Revision 116) defines a interface for upgrading TPM in the field and a command ordinal::

    TPM_RESULT TPM_FieldUpgrade([in, out] TPM_AUTH* ownerAuth, ...);
    TPM_ORD_FieldUpgrade = 0x000000AA

Nevertheless this ordinal is not used by the requests seen in the update firmware.
Instead, several vendor-specific commands are issues.

The TPM update holds 201 TPM requests:

* The first one uses ``tag=0x8001, ord=0x20000200`` (vendor-specific command ``0x200``), with a payload of 316 bytes that can be decoded as 2 blocks prefixed by their sizes:

  - a 42-byte long block, maybe compatible versions? Its content is::

      0044           => 68?
      0102 0551 0201 => TPM version 1.2, Firmware version 5.81.2.1 (the version of this update)
      0000 001e      => 30 bytes (remaining bytes)
      0102 054f 0000 => TPM version 1.2, Firmware version 5.79.0.0
      0102 0551 0000 => TPM version 1.2, Firmware version 5.81.0.0
      0102 0551 0100 => TPM version 1.2, Firmware version 5.81.1.0
      0200 0103 0001 => TPM version 2.0, Firmware version 1.3.0.1
      0200 0103 0100 => TPM version 2.0, Firmware version 1.3.1.0

  - a 256-byte long block (maybe a RSA-2048 encrypted message containing a symmetric cipher key?)

* The 2nd and 3rd requests use ``tag=0xc1, ord=0x20000035`` and seem to define intervals:

  - ``0x88000..0x9ffff`` (98304 = ``0x18000`` bytes)
  - ``0xa0000..0xb2fff`` (77824 = ``0x13000`` bytes)

* The 4th to 200th requests use ``tag=0xc1, ord=0x20000033`` contain what look like chunks of the firmware upgrade, prefixed by a header containing a 16-byte long blob (which can be a MD5 digest, an AES-CBC initialization vector, etc.).

  - all chunks but the last one are 906-byte long (``0x38a``)
  - the last chunk is 522-byte long (``0x20a``)

* The last request uses ``tag=0xc1, ord=0x20000034`` and contains versions and probably digests:

  - "1.2.5.81.2.1" (TPM version 1.2, FW version 5.81.2.1) written ``0102 0551 0201``
  - ``0x10, 0x10, 0x10, eb3058d2d90cc5c21537d5f2364b2d3a`` (probably a digest)
  - ``54d1d69f931a8c731507a1bc9d494b43`` (probably a second 16-byte long digest)
  - a 256-byte long block (maybe a RSA-2048 signature?)

There are 197 requests with chunks of firmware upgrade data, that sum up to 178098 = ``0x2b7b2`` bytes of data.
If the 2nd and 3rd requests define memory interval, there are only ``0x18000 + 0x13000 = 0x2b000`` bytes.
So there are ``0x2b7b2 - 0x2b000 = 0x7b2 = 1970`` bytes too much in the gathered data chunks.
This might mean that there have been 1970/197 = 10 bytes of data too much for each chunk.
In short: the size of each chunk is not 906 or 522 bytes, but 896 (= ``0x380``) or 512 (= ``0x200``) bytes.

Unfortunately, as the entropy of the data chunks is high, it is likely that the payload is encrypted.
The observed 16-byte long blobs associated with each chunk may be initialization vectors for a symmetric cipher.
The key of the cipher might be included in the first request, encrypted using a RSA key.
But without the RSA key which has been used or more vendor-specific documentation, there is no way to be sure about this.
