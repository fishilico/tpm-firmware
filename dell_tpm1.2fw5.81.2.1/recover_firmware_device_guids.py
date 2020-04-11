#!/usr/bin/env python3
"""Recover the information encoded by fwupd in the GUIDs defined in the firmware metadata

fwupd hashes data into UUIDs using an algorithm described in
https://github.com/fwupd/fwupd/blob/1.3.9/libfwupd/fwupd-common.c#L862 :

/**
 * fwupd_guid_hash_string:
 * @str: A source string to use as a key
 *
 * Returns a GUID for a given string. This uses a hash and so even small
 * differences in the @str will produce radically different return values.
 *
 * The default implementation is taken from RFC4122, Section 4.1.3; specifically
 * using a type-5 SHA-1 hash with a DNS namespace.
 * The same result can be obtained with this simple python program:
 *
 *    #!/usr/bin/python
 *    import uuid
 *    print uuid.uuid5(uuid.NAMESPACE_DNS, 'python.org')
 **/

uuid.uuid5(uuid.NAMESPACE_DNS, 'python.org') is 886313e1-3b8a-5372-9b90-0c9aee199e5d
because:
- NAMESPACE_DNS = UUID('6ba7b810-9dad-11d1-80b4-00c04fd430c8')
- SHA1(unhex('6ba7b8109dad11d180b400c04fd430c8') + 'python.org') = '886313e13b8a53725b900c9aee199e5d94d841da'
- Truncation to 16 bytes: 886313e1 3b8a5372 5b900c9a ee199e5d
- Adjustments {uu_new[6] = ((uu_new[6] & 0x0f) | 0x50); uu_new[8] = ((uu_new[8] & 0x3f) | 0x80)}:
  886313e1 3b8a5372 9b900c9a ee199e5d
- split as GUID (with Big Endian encoding): 886313e1-3b8a-5372-9b90-0c9aee199e5d

For Dell TPM firmware, fwupd combines the system_id with the TPM mode ("1.2" or "2.0"):
https://github.com/fwupd/fwupd/blob/1.3.9/plugins/dell/fu-plugin-dell.c#L716

    tpm_guid_raw = g_strdup_printf ("%04x-%s", system_id, tpm_mode);

The system_id is derived from the SMBIOS Product SKU property.

https://github.com/fwupd/fwupd/blob/1.3.9/plugins/dell/README.md#guid-generation
gives some examples:

    TPM GUIDs are also built using the TSS properties TPM2_PT_FAMILY_INDICATOR,
    TPM2_PT_MANUFACTURER, and TPM2_PT_VENDOR_STRING_* These are built
    hierarchically with more parts for each GUID:

    DELL-TPM-$FAMILY-$MANUFACTURER-$VENDOR_STRING_1
    DELL-TPM-$FAMILY-$MANUFACTURER-$VENDOR_STRING_1$VENDOR_STRING_2
    DELL-TPM-$FAMILY-$MANUFACTURER-$VENDOR_STRING_1$VENDOR_STRING_2$VENDOR_STRING_3
    DELL-TPM-$FAMILY-$MANUFACTURER-$VENDOR_STRING_1$VENDOR_STRING_2$VENDOR_STRING_3$VENDOR_STRING_4
    If there are non-ASCII values in any vendor string or any vendor is missing that octet will be skipped.

    Example resultant GUIDs from a real system containing a TPM from Nuvoton:

      Guid: 7d65b10b-bb24-552d-ade5-590b3b278188 <- DELL-TPM-2.0-NTC-NPCT
      Guid: 6f5ddd3a-8339-5b2a-b9a6-cf3b92f6c86d <- DELL-TPM-2.0-NTC-NPCT75x
      Guid: fe462d4a-e48f-5069-9172-47330fc5e838 <- DELL-TPM-2.0-NTC-NPCT75xrls

Moreover there are some examples later in the same file,
https://github.com/fwupd/fwupd/blob/1.3.9/plugins/dell/README.md#switchable-tpm-devices :

    Example (from a Precision 5510):

        Precision 5510 TPM 1.2
          Guid:                 b2088ba1-51ae-514e-8f0a-64756c6e4ffc
          DeviceID:             DELL-b2088ba1-51ae-514e-8f0a-64756c6e4ffclu
          Plugin:               dell
          Flags:                internal|allow-offline|require-ac
          Version:              5.81.0.0
          Created:              2016-07-19

        Precision 5510 TPM 2.0
          Guid:                 475d9bbd-1b7a-554e-8ca7-54985174a962
          DeviceID:             DELL-475d9bbd-1b7a-554e-8ca7-54985174a962lu
          Plugin:               dell
          Flags:                internal|require-ac|locked
          Created:              2016-07-19

These GUID maps the following values:

    b2088ba1-51ae-514e-8f0a-64756c6e4ffc: '06e5-1.2'
    475d9bbd-1b7a-554e-8ca7-54985174a962: '06e5-2.0'

06E5 is indeed the SKU (reference) of a Dell Precision 5510

Result:

    2dddcf05-47bd-53be-9bd6-8633c162b8c5: '06f2-1.2' -> Dell Latitude D620 Intel Core 2 Duo
    f6e202b2-73bf-519a-9b15-1918b8fa82c5: '06f3-1.2' -> Dell Latitude 3570 Laptop i5-6200U 2.30GHz
    aad015ec-26bd-5297-a0c7-b1e2a47cc8e7: '06dd-1.2' -> Dell Latitude E5270 Laptop i5-6300U 2.4GHz
    5e9cb275-bb36-5372-9afc-87c1335f84a6: '06de-1.2' -> Dell Latitude E5470
    58dde259-f0f9-582b-8a3d-6b401b0ac4c0: '06df-1.2' -> Dell Latitude E5570
    0e623ac8-5867-551a-b094-db9d1db4389f: '06db-1.2' -> Dell Latitude E7270 UltraBook i7-6600U 2.60GHz
    b2432fd8-8ab5-5346-907b-aa459bcfd3a9: '06dc-1.2' -> Dell Latitude E7470
    bc4c153b-7398-538e-b182-ed3da1108b69: '06bb-1.2'
    2b764d92-8a21-54f0-a163-81459e644540: '06c6-1.2' -> Dell Optiplex 3240
    9f18e315-6177-5761-87bb-32f6b9cd7de4: '06ba-1.2' -> Dell Optiplex 5040 SFF Desktop PC i5-6500 QC 3.2GHz
    b0fadd9c-013d-5c86-9e33-ba8b74e83b82: '06b9-1.2' -> Dell OptiPlex 7040 SFF Desktop PC i5-6500 QC 3.2GHz
    5ac47548-e32a-54d8-8788-519335d8ae01: '05ca-1.2' -> Dell Latitude E7240
    52a6f885-b7bc-58e0-b8ec-0e0d8170bb0a: '06c7-1.2'
    886d42b8-fb44-5614-99a5-3901745357e4: '06b7-1.2' -> Dell Precision Tower 3620
    403b8d78-84b9-5634-9087-b42090499bd3: '06e0-1.2'
    b2088ba1-51ae-514e-8f0a-64756c6e4ffc: '06e5-1.2'
    057c9e26-7e99-5afd-b128-93d91cc0e957: '06d9-1.2'
    f4bbff03-7ff5-5e38-a0dc-2a7b7b2d5bb4: '06da-1.2'
    9055a777-a92f-55da-8d34-6614d8f9df92: '06e4-1.2'
    d433959e-03ca-524b-92b7-5022eff81a31: '0704-1.2'
    f9bdd338-b410-5e73-902d-7b6e4694bb56: '075b-1.2'
    f06e62b7-7039-5d5d-9c65-f7fccacbafbf: '07a0-1.2'
    bc5450c3-c014-5551-b642-b0703f7ad8a4: '079f-1.2'
    a106730d-d3ff-5369-b79b-6d84f28cbf52: '07a4-1.2'
    64fc7cef-bddd-56c5-8143-3a31617e3db5: '07a5-1.2'
    e9df3399-749e-5e78-bad8-32766cb848c0: '07a6-1.2'
    8e5afbc9-decd-55ed-b6d2-0e5240f88bd4: '07a7-1.2'
    ffcaef00-b480-5014-be2b-635e6c6f6e56: '07a8-1.2'
    225ef49f-e6f8-569c-9cf4-3b140cc9175b: '07a9-1.2'
    16bda90e-f82f-5a00-b001-bf7a71b1ed0d: '07aa-1.2'
    13e484c3-e6d1-510d-9f5d-4e65127f996d: '07ab-1.2'
    25bffbc3-98fd-57fc-891b-328744dfac2d: '07b0-1.2'
    7fc19714-8a9b-5a73-b96b-803a3e6b3dfa: '07b1-1.2'
    e1c76b8c-565f-507e-9186-397a83cc4346: '07b2-1.2'
    6037bb38-64fc-5770-80b1-e1ed8c6fbdb3: '07b4-1.2'
    1e64d0c3-87c6-5318-afa3-353052227664: '07b7-1.2'
    a4bd4e83-0f4e-5c6c-a9ba-177ee33980d2: '07b8-1.2'
    c5e6d7ef-4270-54bf-af0f-8b8ef2a561e6: '07be-1.2'
    61c84b2d-1924-5867-91e2-63ae6a4373af: '07bf-1.2'
    08aa7676-3cc0-528a-ab12-32500bab2aff: '077a-1.2'
    6f948839-4a1c-515a-957f-c6e1bd93f992: '07cf-1.2'
"""
from pathlib import Path
import re
from typing import Dict, List, Set
import uuid


def fwupd_guid(value: str) -> str:
    return str(uuid.uuid5(uuid.NAMESPACE_DNS, value))


assert fwupd_guid('python.org') == '886313e1-3b8a-5372-9b90-0c9aee199e5d'


BASE_DIR = Path(__file__).parent
METAINFO_XML = BASE_DIR / 'extracted' / 'firmware.metainfo.xml'
firmware_guids: List[str] = []
with METAINFO_XML.open('r') as fmeta:
    for line in fmeta:
        matches = re.match(r'^ *<firmware type="flashed">([0-9a-f-]*)</firmware>', line)
        if matches:
            firmware_guids.append(matches.group(1))

if 0:
    # Try the GUIDs documented by fwupd too
    firmware_guids.append('b2088ba1-51ae-514e-8f0a-64756c6e4ffc')
    firmware_guids.append('475d9bbd-1b7a-554e-8ca7-54985174a962')

firmware_guids_remaining_set: Set[str] = set(firmware_guids)
firmware_guids_values: Dict[str, str] = {}

for system_id in range(0x10000):
    for tpm_mode in ('1.2', '2.0'):
        test_value = f'{system_id:04x}-{tpm_mode}'
        test_guid = fwupd_guid(test_value)
        if test_guid in firmware_guids_remaining_set:
            print(f"Found matching device: {test_value!r} -> {test_guid!r}")
            firmware_guids_values[test_guid] = test_value
            firmware_guids_remaining_set.remove(test_guid)
    if not firmware_guids_remaining_set:
        break

print("Mapping:")
for fw_guid in firmware_guids:
    try:
        value4guid = firmware_guids_values[fw_guid]
    except KeyError:
        print(f"    {fw_guid}: not found :(")
    else:
        print(f"    {fw_guid}: {value4guid!r}")

# Everything has been found
assert not firmware_guids_remaining_set
