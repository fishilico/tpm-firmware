Analysis of the update of TPM firmware
======================================

What is it about?
-----------------

TPM (Trusted Platform Module) devices have many features and contain sensitive information.
They can be used to store private keys, encrypt hard drives, attest that the boot went without unexpected components, etc.
Sometimes, vulnerabilities occur, such as ROCA (CVE-2017-15361, https://crocs.fi.muni.cz/public/papers/rsa_ccs17) or https://tpm.fail/ (CVE-2019-11090 and CVE-2019-16863).
As a TPM is a device that runs a firmware, such vulnerabilities might be fixed by upgrading the TPM firmware.

What does a TPM firmware update look like?
How does a TPM check whether the firmware update is legitimate?
For example, are updates signed with a public key which is available?

This project aims at analyzing TPM firmware updates in order to try understanding them.
It appears that all the updates seen so far seem to be encrypted or compressed with an unknown algorithm (the entropy of their contents is high), but research in this area stays nonetheless interesting.


How are firmware updates applied?
---------------------------------

The API (Application Programming Interface) of a TPM is specified by the TCG (Trusted Computing Group).
There are great (and long) specifications publicly available for TPM 1.2 and TPM 2.0 on https://trustedcomputinggroup.org/resources/.
These versions are very different but both provide a way for manufacturer to perform "Field Upgrades", using specific commands:

* TPM 1.2 specifies command code ``TPM_ORD_FieldUpgrade = 0x000000AA``
* TPM 2.0 specifies command codes ``TPM2_CC_FieldUpgradeStart = 0x0000012F`` and ``TPM2_CC_FieldUpgradeData = 0x00000141``, as well as ``TPM2_CC_FirmwareRead = 0x00000179`` to read the current firmware.

Each manufacturer is free to choose whether to implement these commands or to add its own way to update the firmware of the TPM.
Moreover a manufacturer may want to only accept update commands when the system has been started in a state where it can write to some flash memory devices (for example during BIOS or UEFI Boot Services, before the main Operating System).

Where are update founds, anyway?

The ecosystem of firmware updates is quite fragmented.
There exists projects whose goal is to ease downloading and applying updates, such as the LVFS (Linux Vendor Firmware Service, https://fwupd.org/).
But as of April 2020, only one TPM firmware update has been available on the LVFS: update 5.81.2.1 of a Dell TPM 1.2, https://fwupd.org/lvfs/devices/com.dell.uefi5034bac4.firmware.

Most TPM firmware updates are hosted on vendors website:

* Dell publishes firmware updates on its website, such as https://www.dell.com/support/home/fr/fr/frbsdt1/drivers/driversdetails?driverid=rf87d (Dell TPM 2.0 Firmware Update Utility version 1.3.2.8, A02 from 2017-03-21).
* Another manufacturer, ST Microelectronics, distributes TPM firmware updates through OEM such as Lenovo, Dell, Panasonic and HPE.
  For example the patch for CVE-2019-16863 (https://tpm.fail) is described on STM's website on https://www.st.com/content/st_com/en/campaigns/tpm-update.html, which provides links to several OEM.
  In the end, users of HPE systems with TPM from STM can download firmware updates on https://support.hpe.com/hpesc/public/docDisplay?docId=emr_na-a00092108en_us, users of Lenovo systems can use links on https://support.lenovo.com/fr/en/product_security/len-29406, etc.

When the OS needs to apply a firmware update for the TPM, the main mechanisms that exist are:

* Trigger a BIOS firmware update through an OEM-specific procedure (including a reboot into BIOS update mode) and make the BIOS flash the TPM by issuing vendor-specific commands.

  - This is what Dell does when updating its TPM. Here, the BIOS update procedure consists in cutting the update payload into packets with many integrity checksums (CRC), copying each packet 6 times in contiguous physical memory, setting bit 6 (value ``0x40``) of CMOS register ``0x78``, rebooting the system and praying that at least one of the copy is not damaged by the reboot.
  - Sometimes this involves applications for Windows that install a driver that pokes into the physical memory and I/O ports.
    Compatibility with non-Windows systems is handled by also providing a DOS application that can be run with FreeDOS. Gigabyte does this for its BIOS upgrades.

* Trigger a BIOS firmware update through standard interfaces (such as UEFI capsules, that use UEFI Runtime Services to work) and make the BIOS flash the TPM issuing the commands specified for this by the TCG.

  - A TPM update that does this remains to be seen.

* Embed the update in a regular BIOS update.


Querying the TPM version
------------------------

In order to check whether an update has been applied, it is possible to query the TPM for its current firmware version.

* For TPM 1.2, command ``tpm_version`` issues a TPM request with code ``TPM_ORD_GetCapability`` and parameter ``TPM_CAP_VERSION_VAL``.
  The response (structure ``TPM_CAP_VERSION_INFO``) contains:

  - the TCG specification version (such as "TCG version 1.2 specification level 2 errata revision 3")
  - the manufacturer/vendor ID (such as ``0x53544d20`` for "STM ")
  - the firmware revision (such as "13.12")

* For TPM 2.0, command ``tpm2_getcap properties-fixed`` issues a TPM request with code ``TPM2_CC_GetCapability`` and parameter ``TPM_CAP_TPM_PROPERTIES``.
  The response contains a list of TPM properties, such as:

  - ``TPM2_PT_FAMILY_INDICATOR = 0x322e3000`` ("2.0") for the family
  - ``TPM2_PT_REVISION = 116`` ("1.16") and ``TPM2_PT_LEVEL = 0`` of the specification version
  - ``TPM2_PT_MANUFACTURER = 0x53544d20`` ("STM ") for the TPM manufacturer
  - ``TPM2_PT_FIRMWARE_VERSION_1 = 0x47000c`` (71.12) and ``TPM2_PT_FIRMWARE_VERSION_2 = 0x44a01004`` (17568.4100) for the firmware version
  - ``TPM2_PT_VENDOR_STRING_1``, ``TPM2_PT_VENDOR_STRING_2``, ``TPM2_PT_VENDOR_STRING_3``, ``TPM2_PT_VENDOR_STRING_4`` for vendor-specific strings
  - ``TPM2_PT_YEAR = 2016`` and ``TPM2_PT_DAY_OF_YEAR = 15`` for some date associated with the firmware

For TPM 2.0 with an EKCert (Endorsement Key certificate, handle ``0x01c00002``), the precise commercial part number is included in the certificate that can be retrieved from the TPM::

    # Example on a ST Microelectronics TPM 2.0 from a Lenovo T470 laptop
    # (product line ST33TPHF2ESPI part number ST33HTPxAHB6)

    $ tpm2_nvread 0x01c00002 | openssl x509 -noout -text -inform DER
    [...]
    Issuer: C = CH, O = STMicroelectronics NV, CN = STM TPM EK Intermediate CA 05
    X509v3 extensions:
        X509v3 Subject Alternative Name: critical
            DirName:/2.23.133.2.1=id:53544D20/2.23.133.2.2=ST33HTPxAHB6/2.23.133.2.3=id:0047000C

    # OID 2.23.133.2 is joint-iso-itu-t(2) international-organizations(23) 133 tcg-attribute(2)
    # 2.23.133.2.1 = tcg-at-tpmManufacturer
    # 2.23.133.2.2 = tcg-at-tpmModel
    # 2.23.133.2.3 = tcg-at-tpmVersion
