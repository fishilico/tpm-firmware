Analysis of the Windows executable
==================================

Usage::

    TPM Update Utility - General Usage:
    <Filename>.exe [/<option1>[=<value1>]] [/<option2>[=<value2>]]...
    See listing below for <option> and <value> information.

    Option Descriptions:
     (none)          - A Guided TPM Update with messages.
     /? or /h        - Display this help screen.
     /b=<TPM file>   - Get the TPM update payload from this file.
     /s              - Suppress the user interface during the TPM update.
     /s /f           - Override soft dependency errors during TPM Update.
     /s /r           - Reboot the system to complete the update.
     /s /l=<path>    - Log messages to this file.
     /p=<password>   - Provide the BIOS password, if needed, for the TPM update.

    Examples:
       Update the system silently and Log messages
         <Filename>.exe /s /r
       Log messages to a specific file
         <Filename>.exe /s /r /l="C:\my path with spaces\log.txt",

The program:

* ensures that the user is an administrator by checking that it belongs to group S-1-5-32-544 (Built-in Administrators) with ``CheckTokenMembership`` from ``Advapi32.dll``.

* gathers the SMBIOS table by calling ``GetSystemFirmwareTable(FirmwareTableProviderSignature='RSMB', FirmwareTableID=0, buffer, size)`` from ``kernel32.dll``.

* extracts a driver named ``DBUtil_2_3.Sys`` from its data (xored with key ``0xD4C783A6E9AD96B0`` which is rotated right 3 for each byte) and load it, in order to access to functions.

* uses this driver to send commands to some I/O ports that are referenced through SMBIOS table 0xDA (= 218)

* uses oriented-object C to abstract the operations, with ``puts("ASSERTION FAILED ...");loop_forever();`` when problem occurs. The objects use 32-bit tags such as ``'dRnE'`` for ``EnhancedFileReader.c``, ``'RaMV'`` for ``ManifestReader.c``, ``'tBMS'`` for ``SmbiosTableReader.c``, etc.

* creates a mutex named ``"Global\\DELL_BIOS_FLASH_MUL_INSTANCE_MUTEX"``

* uses the driver to query whether an AC adapter is plugged, the battery is charged above 10%, the TPM has a version that matches the update, etc.

* decompresses the firmware update and extract it to "Flash Packets"

  - Each packets span at most 4096 bytes and start with a 64-byte header.
  - The signature of the header (first 8 bytes) is ``"FPK.FST."`` for the first packet, ``"FPK.MID."`` for the middle ones and ``"FPK.LST."`` for the last one.
  - Then there are information such as the index of the packet, its size, its CRC-32
  - The last field of the header is a xor-checksum (the XOR of all DWORDs is zero)
  - The uploader writes 6 times the packets into physical memory, maybe in hope it will be more easily dicoverable.

* uses the driver to modify a CMOS register: ``CMOS[0x78] |= 0x40``.

  - Reading from the register is done with ``out_byte(port=0x70, reg_idx=0x78), value = in_byte(port=0x71)``
  - Writing to the register is done with ``out_byte(port=0x70, reg_idx=0x78), out_byte(port=0x71, new_value)``
  - Searching "Dell 0x70 0x78" in Google reveals some documentation in http://lists.us.dell.com/pipermail/linux-poweredge/2007-May/030990.html ::

      this is the token listing. use with activateCmosToken or tokenCtl binaries.

      > DMI type 0xd4  Handle 0xd400  Index Port 0x70  Data Port 0x71  Type 0x005c  
      > Location 0x78 AND(bf) OR(40)  BITFIELD: 0

      use dellBiosUpdate -- do not manually set
      remote bios update -- enable

  - so this register seems to enable a remote BIOS update feature specific to Dell's BIOS.

* reboots (if there was no ``/noreboot`` option) by enabling ``SeShutdownPrivilege`` and running ``ExitWindowsEx(EWX_FORCEIFHUNG|EWX_REBOOT, 0)`` if registry key ``HKLM\System\ControlSet001\Control\MiniNT`` does not exist, ``NtShutdownSystem(ShutdownReboot=1)`` otherwise.


File headers
------------

MZDOS header::

    e_magic = 0x5a4d
    e_cblp = 0x1b8
    e_cp = 0x14d
    e_crlc = 0x766
    e_cparhdr = 0x1e0
    e_minalloc = 0x402
    e_maxalloc = 0xffff
    e_ss = 0x27bd
    e_sp = 0x4000
    e_ip = 0x3ca
    e_cs = 0x1a5
    e_lfarlc = 0x40
    e_ovno = 0
    e_res = [1, 0, 1, 0]
    e_lfanew = 0x29a40

``e_lfanew`` is quite large.
There is indeed some 16-bit code at the beginning of the executable, instead of the usual DOS stub.
This code seems to perform the same operations as the Windows file, but as a DOS executable.
This induces some changes, like the way the program access the physcical memory: it disables the protected mode, uses the eXtended Memory Specification (XMS) is a function at offset ``0x11D76`` that does ``mov ax, 4310h; int 2Fh`` to retrieve the driver entry point of HIMEM.SYS, etc.

The PE header is located at ``0x29a40``.
Here are interesting fields (with ``i686-w64-mingw32-objdump -x``)::

    Time/Date               Wed Aug 12 22:12:38 2015
    SizeOfCode              0001ba00
    SizeOfInitializedData   0001a600
    SizeOfUninitializedData 00000000
    AddressOfEntryPoint     0003c881
    BaseOfCode              0002a000
    BaseOfData              00046000
    ImageBase               00400000
    MajorOSystemVersion     5
    MinorOSystemVersion     1
    SizeOfImage             00063000
    SizeOfHeaders           00029c00

PE File mapping::

    0x000000..0x029a40: MZDOS header + some code
    0x029a40..0x029c00: PE header for a x86 Windows executable
    0x029c00..0x045600 (113152 bytes) rva 0x02a000..0x04591e (112926 bytes): .text
    0x045600..0x04e800 ( 37376 bytes) rva 0x046000..0x04f0e4 ( 37092 bytes): .rdata
    0x04e800..0x056e00 ( 34304 bytes) rva 0x050000..0x05ea84 ( 60036 bytes): .data
    0x056e00..0x057200 (  1024 bytes) rva 0x05f000..0x05f388 (   904 bytes): .rsrc
    0x057200..0x059600 (  9216 bytes) rva 0x060000..0x062244 (  8772 bytes): .reloc
    0x059600..0x059800: padding with ffff...
    0x059800..0x0867a0: Flash Payload (markers and compressed payload)


Drivers
-------

There are two drivers for 32-bit and 64-bit versions:

* Timestamp in PE header : "2009-11-03 05:17:17" and "2009-11-03 05:14:51" (UTC)
* Authenticode certificate chain (same for both files, from root of trust to signing certificate):

  - C=US,ST=Washington,L=Redmond,O=Microsoft Corporation,CN=Microsoft Code Verification Root
  - C=US,O=VeriSign, Inc.,OU=Class 3 Public Primary Certification Authority (from 2006-05-23 to 2016-05-23)
  - C=US,O=VeriSign, Inc.,OU=VeriSign Trust Network,OU=Terms of use at https://www.verisign.com/rpa (c)04,CN=VeriSign Class 3 Code Signing 2004 CA (from 2004-07-16 to 2014-07-15)

* Authenticode counter signature from C=US,O=VeriSign, Inc.,CN=VeriSign Time Stamping Services: "2009-11-03 05:18:32" and "2009-11-03 05:19:10"

* Debug path:

  - ``c:\data\work\tools\_efitools\trunk\ringzeroaccesslibrary\win\kernelmodedriver\objfre_wlh_x86\i386\DBUtilDrv2_32.pdb``
  - ``c:\data\work\tools\_efitools\trunk\ringzeroaccesslibrary\win\kernelmodedriver\objfre_wlh_amd64\amd64\DBUtilDrv2_64.pdb``

The 64-bit driver:

* starts by computing a stack cookie from the value at address ``0xFFFFF78000000320`` (this is in the Shared system page (``0xFFFFF78000000000``), offset ``0x320`` is ``KSYSTEM_TIME TickCount``)
* creates device ``"\\Device\\DBUtil_2_3"`` with symbolic link ``\\DosDevices\\DBUtil_2_3"``
* registers a function to handle ``IRP_MJ_{SHUTDOWN,CREATE,CLOSE,DEVICE_CONTROL}``
* initializes a DPC (Deferred Procedure Call) that performs some I/O on ports, which is available through a device extension.


The function that handles IRP mainly handles ``IRP_MJ_DEVICE_CONTROL``.
An IOCTL code is encoded using:

.. code-block:: c

    #define CTL_CODE( DeviceType, Function, Method, Access ) (                 \
        ((DeviceType) << 16) | ((Access) << 14) | ((Function) << 2) | (Method) \
    )
    #define METHOD_BUFFERED                0
    #define METHOD_IN_DIRECT               1
    #define METHOD_OUT_DIRECT              2
    #define METHOD_NEITHER                 3
    #define FILE_ANY_ACCESS                0
    #define FILE_READ_ACCESS               0x0001
    #define FILE_WRITE_ACCESS              0x0002

For example ``0x9B0C1EC0 = CTL_CODE(devtype=0x9b0c, FILE_ANY_ACCESS=0, fct=0x7b0, method=METHOD_BUFFERED)``

* ioctl ``0x9B0C1EC0`` (``0x30`` bytes): call ``MmAllocateContiguousMemorySpecifyCache(size, LowestAcceptableAddress)`` and returns a pointer and the associated physical address
* ioctl ``0x9B0C1EC4`` (at least ``0x18`` bytes): read from kernel memory (using ``memmove``)
* ioctl ``0x9B0C1EC8`` (at least ``0x18`` bytes): write to kernel memory (using ``memmove``)
* ioctl ``0x9B0C1ECC`` (``0x18`` bytes): call ``MmFreeContiguousMemorySpecifyCache`` and set the address in the I/O request buffer to ``NULL``
* ioctl ``0x9B0C1F00`` (``0x48`` bytes): send an SMI or output to a port, specifying the values of registers ``rax``, ``rbx``, ``rcx``, ``rdx``, ``rsi`` and ``rdi``, and using ``wbinvd;in al,0x81;out 0x81,al`` to flush cache and wait for RAM.
* ioctl ``0x9B0C1F04`` (``0x48`` bytes): queue a DPC (Deferred Procedure Call) to perform an SMI or to output a value to a port, like ``0x9B0C1F00``
* ioctl ``0x9B0C1F08`` (``0x48`` bytes): do nothing
* ioctl ``0x9B0C1F40`` (at least ``0x10`` bytes): read from physical memory (using ``MmMapIoSpace`` and ``rep movsb``)
* ioctl ``0x9B0C1F44`` (at least ``0x10`` bytes): write to physical memory (using ``MmMapIoSpace`` and ``rep movsb``
* ioctl ``0x9B0C1F80`` (``0x18`` bytes): receive 1, 2 or 4 bytes from an I/O port
* ioctl ``0x9B0C1F84`` (``0x18`` bytes): send 1, 2 or 4 bytes to an I/O port
* ioctl ``0x9B0C1F88`` (``0x18`` bytes): send some bytes to an I/O port and receive some bytes from an I/O port
* ioctl ``0x9B0C1F8C`` (``0x18`` bytes): send some bytes to an I/O port and receive 1, 2 or 4 bytes from an I/O port
* ioctl ``0x9B0C1FC0`` (``0xc`` bytes): return the version (2.3) and whether the device is associated (whether a nonce is defined)
* ioctl ``0x9B0C1FC4`` (``8`` bytes): associate a nonce value to the device, in order to lock its use for the future requests (other users get ``STATUS_ACCESS_VIOLATION`` if they try to issue requests)

The structures are detailed in `<structures.h>`_, which is a C header file suitable for reverse-engineering and writing code which interacts with the driver.
