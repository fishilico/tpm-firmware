Analysis of the update of Dell TPM 2.0 firmware update 1.3.2.8
==============================================================

Description
-----------

Dell published on 2017-12-19 a TPM 2.0 firmware update utility: https://www.dell.com/support/home/fr/fr/frbsdt1/drivers/driversdetails?driverid=rf87d

Version 1.3.2.8, A02 downloaded from https://dl.dell.com/FOLDER04166647M/1/DellTpm2.0_Fw1.3.2.8_V1_64.exe (SHA256 29cf9f45fed94d03d2aa8a6a0920fc547613a2ab93de1c8e2c597a3b9dd33c53).

The executable is a DOS application (in 16-bit) as well as a x86-64 application for Windows, signed until offset ``0x61600``.
The timestamp in the PE header is 2015-08-12 20:13:13 UTC and has been signed with a counter-signature timestamp on 2017-02-03 20:28:21 UTC.
This application embeds the same drivers as another firmware update that has been studied more thoroughly (`<../dell_tpm1.2fw5.81.2.1/windows_executable.rst>`_).

``binwalk`` shows some zlib compressed data at offset ``0x61810`` and the compressed content starts with ``PFS.HDR.`` and ends with ``PFS.FTR.``.
This is a Dell firmware partition, whose format is described in another firmware update: `<../dell_tpm1.2fw5.81.2.1/README.rst>`_.

More precisely, the file update contains::

    00061800: c696 0300 aaee aa76 1bec bb20 f1e6 51e1
              ^^^^^^^^^--------------------------------- size of the Flash Payload
                        ^^^^^^^^^^^^^^^^^^^^^^^^^^^----- Start marker
                                                   ^^--- Checksum (the XOR of the 16 bytes is 0)
    [Zlib-compressed content from 00061810 to 0009aed6]
    0009aed0: fe0f 2e79 cff6 c696 0300 eeaa ee8f 491b
                             ^^^^^^^^^------------------ size of the Flash Payload
                                       ^^^^^^^^^^^^^^--- End marker
    0009aee0: e8ae 1437 90d1 0000 5019 0000 0002 0200
              ^^^^^^^^^^^^------------------------------ End marker
                          ^^---------------------------- Checksum (the XOR of the 16 bytes is 0)
                             ^^^^^^^^^^^^^^^^^^^^^^^^--- Start of PE's Attribute Certificate Table
                                                         (Authenticode signature)

The Flash Payload is similar to what is described in `<../dell_tpm1.2fw5.81.2.1/README.rst>`_.
Its mapping is::

    [000000..000010] PFS header (b'PFS.HDR.', spec=1, size=240802)
    [000010..03ab38] Section (240424 bytes)
      [000010..000058] Section header (GUID=c22d63f4-f182-40fc-b238-e5f89fbf3b87, spec=1, version=1.3.2.8)
      [000058..03aa38] Data (240096 bytes, CRC=0xa55cdcfb)
        ... TPM 2 Update
      [03aa38..03ab38] RSA 1 (256 bytes, CRC=0x41a45111)
    [03ab38..03acb2] Section (378 bytes)
      [03ab38..03ab80] Section header (GUID=4d583fd3-f80e-4055-a145-9bec16cb33b0, spec=1, version=1.0.0.0)
      [03ab80..03abb2] Data (50 bytes, CRC=0x64e5dd5b)
        ... Update Manifest
      [03abb2..03acb2] RSA 1 (256 bytes, CRC=0xb977f3cc)
    [03acb2..03acc2] PFS footer (b'PFS.FTR.', size=240802, CRC=0x38e51ebc)

    PFS manifest:
    * spec = 1
    * data GUID = c22d63f4-f182-40fc-b238-e5f89fbf3b87
    * version = 1.3.2.8
    * description = 'TPM 2.0'

The TPM 2 Update (GUID c22d63f4-f182-40fc-b238-e5f89fbf3b87) contains several TPM 1.2 commands.
Yes, these ARE TPM 1.2 commands, even though they are targeted to a TPM 2.0::

    [000000..000142] TPM request: tag=0xc1, ord=0xaa, 322 bytes
        => TPM 1.2 request with command ordinal TPM_ORD_FieldUpgrade

      [0000..0034] sub-block (48 bytes): 0044-0200-0103 0208-0000-0024 0200-0103-0001 0200-0103-0100 0102-054f-0000 0102-0551-0000 0102-0551-0100 0102-0551-0201

        maybe compatible versions?
          0044           => structure tag 0x0044?
          0200 0103 0208 => TPM version 2.0, Firmware version 1.3.2.8 (the version of this update)
          0000 0024      => 36 bytes (remaining bytes)
          0200 0103 0001 => TPM version 2.0, Firmware version 1.3.0.1
          0200 0103 0100 => TPM version 2.0, Firmware version 1.3.1.0
          0102 054f 0000 => TPM version 1.2, Firmware version 5.79.0.0
          0102 0551 0000 => TPM version 1.2, Firmware version 5.81.0.0
          0102 0551 0100 => TPM version 1.2, Firmware version 5.81.1.0
          0102 0551 0201 => TPM version 1.2, Firmware version 5.81.2.1

      [0034..0138] sub-block (256 bytes): 4386cf8880...52c0

    [000142..000154] TPM request: tag=0xc1, ord=0x20000035, 18 bytes
      [0000..0008] interval: 0x88000..0x9ffff (98304=0x18000 bytes)

    [000154..000166] TPM request: tag=0xc1, ord=0x20000035, 18 bytes
      [0000..0008] interval: 0xa0000..0xb7fff (98304=0x18000 bytes)

    [000166..000178] TPM request: tag=0xc1, ord=0x20000035, 18 bytes
      [0000..0008] interval: 0xb8000..0xbefff (28672=0x7000 bytes)

    [000178..000530] TPM request: tag=0xc1, ord=0x20000033, 952 bytes
      [0000..0020] digest or IV (28 bytes): 0x10, 0x10, 0x10, e46680a9b22229c29c922d5a296abea4
      [0020..03ae] data (906 bytes): 7e8e6b8d9d...cdc3

    [000530..0008e8] TPM request: tag=0xc1, ord=0x20000033, 952 bytes
      [0000..0020] digest or IV (28 bytes): 0x10, 0x10, 0x10, 5893264cfa0b063e330e9a2f57cf6987
      [0020..03ae] data (906 bytes): 0344d1b898...6d81
    ...
    [03a6e0..03a898] TPM request: tag=0xc1, ord=0x20000033, 440 bytes
      [0000..0020] digest or IV (28 bytes): 0x10, 0x10, 0x10, 7b973f391635aaca1578c4db22753a82
      [0020..01ae] data (394 bytes): 4d37035a55...dfaa

    [03a898..03a9e0] TPM request: tag=0xc1, ord=0x20000034, 328 bytes
      [0000..0002] TPM version 2.0
      [0002..0006] FW version 1.3.2.8
      [0006..0026] digest or IV (28 bytes): 0x10, 0x10, 0x10, 22ae62a01ff94a3b9272684c1f5495e2
      [0026..003a] probably digest (16 bytes): 1ca6c487a39519a4f72e5ccb4e297a59
      [003a..013e] sub-block (256 bytes): 6ba5056627...b1d4

There are 252 requests with chunks of firmware upgrade data, that sum up to 227800 = ``0x379d8`` bytes of data.
By removing 10 bytes for each chunk, this size goes down to 225280 = ``0x37000``, which is the sum of the sizes of the interval that were defined: ``0x88000..0x9ffff`` + ``0xa0000..0xb7fff`` + ``0xb8000..0xbefff``.
