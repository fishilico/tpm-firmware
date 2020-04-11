/**
 * Structures used for interacting with Dell's TPM update program and its
 * "ring zero access library" driver.
 */
#pragma pack(push, 1)

typedef unsigned char BYTE, uchar;
typedef unsigned short WORD, ushort;
typedef unsigned int DWORD, uint;
typedef unsigned long long QWORD;

#ifdef NOT_IN_IDA
#define STATIC_ASSERT(cond) _Static_assert(cond, #cond)

/* User-space is 32-bit */
#ifndef __x86_64__
#define FOR_USER_SPACE_32
#endif

#else
#define STATIC_ASSERT(cond)
#endif
STATIC_ASSERT(sizeof(BYTE) == 1);
STATIC_ASSERT(sizeof(WORD) == 2);
STATIC_ASSERT(sizeof(DWORD) == 4);
STATIC_ASSERT(sizeof(QWORD) == 8);

/* Define some types to make this header free-standing (not depending on stdio.h or windows.h) */
#define __cdecl
#define FILE void
typedef void *HWND, *HBRUSH;
typedef long LONG;
typedef struct tagRECT {
    LONG left;
    LONG top;
    LONG right;
    LONG bottom;
} RECT;
typedef struct tagUUID {
    DWORD Data1;
    WORD Data2;
    WORD Data3;
    BYTE Data4[8];
} UUID;
STATIC_ASSERT(sizeof(UUID) == 0x10);


enum DBUTIL_IOCTL {
    DBUTIL_9B0C1EC0_Allocate_Contiguous_Memory = 0x9B0C1EC0,
    DBUTIL_9B0C1EC4_Read_Kernel_Memory = 0x9B0C1EC4,
    DBUTIL_9B0C1EC8_Write_Kernel_Memory = 0x9B0C1EC8,
    DBUTIL_9B0C1ECC_Free_Contiguous_Memory = 0x9B0C1ECC,

    DBUTIL_9B0C1F00_SMI_Or_Out_Port = 0x9B0C1F00,
    DBUTIL_9B0C1F04_Queue_DPC_for_SMI_Or_Out_Port = 0x9B0C1F04,
    DBUTIL_9B0C1F08_do_nothing_with_arg_like_SMI_Or_Out_Port = 0x9B0C1F08,

    DBUTIL_9B0C1F40_Read_Phys_Memory = 0x9B0C1F40,
    DBUTIL_9B0C1F44_Write_Phys_Memory = 0x9B0C1F44,

    DBUTIL_9B0C1F80_In_Port = 0x9B0C1F80,
    DBUTIL_9B0C1F84_Out_Port = 0x9B0C1F84,
    DBUTIL_9B0C1F88_OutOther_In_Port = 0x9B0C1F88,
    DBUTIL_9B0C1F8C_OutOther_Out_Port = 0x9B0C1F8C,

    DBUTIL_9B0C1FC0_Get_Version = 0x9B0C1FC0,
    DBUTIL_9B0C1FC4_Associate_With_Nonce = 0x9B0C1FC4,
};

struct DBUTIL_IOCTL_ALLOCATE_CONTIGUOUS_MEMORY {
    QWORD nonce;
    DWORD in_size;
    DWORD _in_size_padding;
    QWORD in_LowestAcceptableAddress;
    QWORD in_HighestAcceptableAddress;
    QWORD out_ptr_mem;
    QWORD out_phys_addr;
};
STATIC_ASSERT(sizeof(struct DBUTIL_IOCTL_ALLOCATE_CONTIGUOUS_MEMORY) == 0x30);

struct DBUTIL_IOCTL_FREE_CONTIGUOUS_MEMORY {
    QWORD nonce;
    QWORD base_address;
    DWORD size;
    DWORD _size_padding;
};
STATIC_ASSERT(sizeof(struct DBUTIL_IOCTL_FREE_CONTIGUOUS_MEMORY) == 0x18);

struct DBUTIL_IOCTL_RW_KERNEL_MEMORY {
    QWORD nonce;
    QWORD base_address;
    DWORD offset;
    DWORD _offset_padding;
    BYTE data[];
};
STATIC_ASSERT(sizeof(struct DBUTIL_IOCTL_RW_KERNEL_MEMORY) == 0x18);

struct DBUTIL_IOCTL_RW_PHYS_MEMORY {
    QWORD nonce;
    QWORD physical_address;
    BYTE data[];
};
STATIC_ASSERT(sizeof(struct DBUTIL_IOCTL_RW_PHYS_MEMORY) == 0x10);

struct DBUTIL_IOCTL_IO_PORT {
    QWORD nonce;
    DWORD value_size__1_2_4;
    WORD port_otherout;
    WORD port;
    DWORD value_otherout; /* value which is output to IO port_otherout */
    DWORD value; /* value which is input or output to IO port */
};
STATIC_ASSERT(sizeof(struct DBUTIL_IOCTL_IO_PORT) == 0x18);

struct DBUTIL_IOCTL_GET_VERSION {
    DWORD version_major__2;
    DWORD version_minor__3;
    DWORD was_nonce_defined;
};
STATIC_ASSERT(sizeof(struct DBUTIL_IOCTL_GET_VERSION) == 0xc);

/* Registers for int 0xb2 (SMI) or other port I/O used by DPC */
struct DPC_SMI_PORT_REGISTERS {
    QWORD rax__smi_code_in_port_0xb2;
    QWORD rbx;
    QWORD rcx;
    QWORD rdx;
    QWORD rsi;
    QWORD rdi;
};
STATIC_ASSERT(sizeof(struct DPC_SMI_PORT_REGISTERS) == 0x30);

struct DBUTIL_IOCTL_DPC {
    QWORD nonce;
    struct DPC_SMI_PORT_REGISTERS dpc_smi_registers;
    DWORD size_of_value_to_port_out; /* 1, 2 or 4 bytes */
    DWORD do_smi; /* 1 to do int 0xb2 (SMI), 0 to send al/ax/eax to port dx, from registers */
    QWORD out_successful;
};
STATIC_ASSERT(sizeof(struct DBUTIL_IOCTL_DPC) == 0x48);

union DBUTIL_IOCTL_BUFFER {
    QWORD nonce;
    struct DBUTIL_IOCTL_ALLOCATE_CONTIGUOUS_MEMORY Allocate_Contiguous_Memory;
    struct DBUTIL_IOCTL_FREE_CONTIGUOUS_MEMORY Free_Contiguous_Memory;
    struct DBUTIL_IOCTL_RW_KERNEL_MEMORY RW_Kernel_Memory;
    struct DBUTIL_IOCTL_RW_PHYS_MEMORY RW_Phys_Memory;
    struct DBUTIL_IOCTL_IO_PORT IO_Port;
    struct DBUTIL_IOCTL_DPC Request_DPC;
    struct DBUTIL_IOCTL_GET_VERSION Get_Version;
};

struct DBUTIL64_DEVICE_EXT {
    union DBUTIL_IOCTL_BUFFER *ioctl_request_buffer;
    DWORD ioctl_request_buffer_size;
    DWORD _ioctl_request_buffer_size_padding;
    QWORD nonce;
    QWORD DPC_for_deferred_routine[8]; /* structure KDPC */
    struct DBUTIL_IOCTL_DPC dpc_argument;
};
#ifdef __x86_64__
/* The pointer size is only valid on 64 bits */
STATIC_ASSERT(sizeof(struct DBUTIL64_DEVICE_EXT) == 0xa0);
#endif

/* Helper functions from the program */
struct USERLAND_TRACKING_OF_ALLOCATED_CONT_MEM {
    struct USERLAND_TRACKING_OF_ALLOCATED_CONT_MEM *next;
    struct USERLAND_TRACKING_OF_ALLOCATED_CONT_MEM *prev;
    DWORD handle;
    DWORD _handle_padding;
    QWORD virt_addr;
    DWORD size;
    DWORD _size_padding;
    QWORD phys_addr;
};
#ifdef FOR_USER_SPACE
STATIC_ASSERT(sizeof(struct USERLAND_TRACKING_OF_ALLOCATED_CONT_MEM) == 0x28);
#endif

struct DBUTIL_DRIVER_FUNC {
    int (*DBUtil_disassociate_with_driver)(void);
    int (*DBUtil_associate_with_driver)(void);
};
struct DBUTIL_IO_PORT_FUNC {
    int (*__cdecl DBUtil_port_in_u8)(WORD port, BYTE *value);
    int (*__cdecl DBUtil_port_in_u16)(WORD port, WORD *value);
    int (*__cdecl DBUtil_port_in_u32)(WORD port, DWORD *value);
    int (*__cdecl DBUtil_port_out_and_in_u8)(WORD otherport, BYTE value_otherout, WORD port, BYTE *value);
    int (*__cdecl DBUtil_port_out_and_in_u16)(WORD otherport, WORD value_otherout, WORD port, WORD *value);
    int (*__cdecl DBUtil_port_out_and_in_u32)(WORD otherport, DWORD value_otherout, WORD port, DWORD *value);
    int (*__cdecl DBUtil_port_out_u8)(WORD port, BYTE value);
    int (*__cdecl DBUtil_port_out_u16)(WORD port, WORD value);
    int (*__cdecl DBUtil_port_out_u32)(WORD port, DWORD value);
    int (*__cdecl DBUtil_port_out_and_out_u8)(WORD otherport, BYTE value_otherout, WORD port, BYTE value);
    int (*__cdecl DBUtil_port_out_and_out_u16)(WORD otherport, WORD value_otherout, WORD port, WORD value);
    int (*__cdecl DBUtil_port_out_and_out_u32)(WORD otherport, DWORD value_otherout, WORD port, DWORD value);
};
struct DBUTIL_RW_PHYS_MEM_FUNC {
    int (*__cdecl DBUtil_read_phys_mem)(QWORD physical_address, void *buffer, DWORD size);
    int (*__cdecl DBUtil_write_phys_mem)(QWORD physical_address, void *buffer, DWORD size);
};
struct DBUTIL_DPC_IO_PORT_FUNC {
    int (*__cdecl DBUtil_do_DPC_io_port_out_u8)(WORD port, BYTE value, QWORD *rax, QWORD *rbx, QWORD *rcx, QWORD *rdx, QWORD *rsi, QWORD *rdi, int fRunInLoop);
    int (*__cdecl DBUtil_do_DPC_io_port_out_u16)(WORD port, WORD value, QWORD *rax, QWORD *rbx, QWORD *rcx, QWORD *rdx, QWORD *rsi, QWORD *rdi, int fRunInLoop);
    int (*__cdecl DBUtil_do_DPC_io_port_out_u32)(WORD port, DWORD value, QWORD *rax, QWORD *rbx, QWORD *rcx, QWORD *rdx, QWORD *rsi, QWORD *rdi, int fRunInLoop);
    int (*__cdecl DBUtil_do_DPC_SMI_0xb2)(BYTE value, QWORD *rax, QWORD *rbx, QWORD *rcx, QWORD *rdx, QWORD *rsi, QWORD *rdi, int fRunInLoop);
};
struct DBUTIL_CONT_MEM_FUNC {
    int (*__cdecl DBUtil_allocate_contiguous_memory)(DWORD size, QWORD LowestAcceptableAddress, QWORD HighestAcceptableAddress, DWORD *contmem_handle, QWORD *physical_address);
    int (*__cdecl DBUtil_do_read_mem_from_contmem)(void *buffer, DWORD offset, DWORD size, DWORD handle);
    int (*__cdecl DBUtil_do_write_mem_to_contmem)(DWORD handle, DWORD offset, DWORD size, void *buffer);
    int (*__cdecl DBUtil_do_write_mem_by_chunks_to_contmem)(DWORD handle, int offset, unsigned int size, void *buffer, unsigned int adjustment);
    int (*__cdecl DBUtil_free_contiguous_memory)(DWORD handle);
};
struct DBUTIL_FUNCTIONS {
    struct DBUTIL_DRIVER_FUNC *driver_functions;
    struct DBUTIL_IO_PORT_FUNC *io_port_functions;
    struct DBUTIL_RW_PHYS_MEM_FUNC *rw_phys_mem_functions;
    struct DBUTIL_DPC_IO_PORT_FUNC *dpc_io_port_functions;
    struct DBUTIL_CONT_MEM_FUNC *contiguous_memory_functions;
};


/**
 * List structure
 */
struct LIST_HEADER {
    struct LIST_HEADER *next;
    struct LIST_HEADER *prev;
};
#ifdef FOR_USER_SPACE_32
STATIC_ASSERT(sizeof(struct LIST_HEADER) == 8);
#endif

/**
 * DBUtil helpers for interacting with physically-contiguous memory.
 * There are also others functions in the program that use a similar interface but work on usual memory (with malloc/free/memcpy)
 */
struct DBUTIL_CONT_MEMORY_AFRW_HELPERS {
    BYTE (*__cdecl Wird__allocate_contmemory)(WORD *wHandleToWird, DWORD *physical_addr_low32, unsigned int *aligned_size, unsigned int size);
    void (*__cdecl Wird__free_contmemory)(WORD wHandleToWird, unsigned int phys_addr);
    BYTE (*__cdecl Wird__read_from_contmemory)(void *buffer, WORD wHandleToWird, unsigned int phys_addr, DWORD offset, DWORD size);
    BYTE (*__cdecl Wird__write_to_contmemory)(WORD wHandleToWird, unsigned int phys_addr, DWORD offset, void *buffer, DWORD size);
};
#ifdef FOR_USER_SPACE_32
STATIC_ASSERT(sizeof(struct DBUTIL_CONT_MEMORY_AFRW_HELPERS) == 0x10);
#endif

struct ALLOC_HANDLE_MEM_FCTS { // DEPRECATED
    struct DBUTIL_CONT_MEMORY_AFRW_HELPERS helpers;
};
#ifdef FOR_USER_SPACE_32
STATIC_ASSERT(sizeof(struct ALLOC_HANDLE_MEM_FCTS) == 0x10);
#endif
struct Wird_list_item {
    struct LIST_HEADER list_header;
    DWORD tag__driW;
    DWORD size;
    QWORD contiguous_mem_phys_addr;
    DWORD contiguous_mem_handle;
    DWORD unk_field_1c;
};
#ifdef FOR_USER_SPACE_32
STATIC_ASSERT(sizeof(struct Wird_list_item) == 0x20);
#endif

/**
 * Structures from https://wiki.osdev.org/System_Management_BIOS
 */
struct SMBIOSEntryPoint {
    char EntryPointString[4];    //This is _SM_
    uchar Checksum;              //This value summed with all the values of the table, should be 0 (overflow)
    uchar Length;                //Length of the Entry Point Table. Since version 2.1 of SMBIOS, this is 0x1F
    uchar MajorVersion;          //Major Version of SMBIOS
    uchar MinorVersion;          //Minor Version of SMBIOS
    ushort MaxStructureSize;     //Maximum size of a SMBIOS Structure (we will se later)
    uchar EntryPointRevision;    //...
    char FormattedArea[5];       //...
    char EntryPointString2[5];   //This is _DMI_
    uchar Checksum2;             //Checksum for values from EntryPointString2 to the end of table
    ushort TableLength;          //Length of the Table containing all the structures
    uint TableAddress;	         //Address of the Table
    ushort NumberOfStructures;   //Number of structures in the table
    uchar BCDRevision;           //Unused
};
STATIC_ASSERT(sizeof(struct SMBIOSEntryPoint) == 0x1f);

struct SMBIOSHeader {
    uchar Type;
    uchar Length;
    ushort Handle;
};
STATIC_ASSERT(sizeof(struct SMBIOSHeader) == 4);

/* payload of SMBIOS table type 0xDA */
struct SMBIOS_table_DA_substructure {
    WORD field_0_maybe_kind;
    WORD field_2;
    WORD field_4;
};
STATIC_ASSERT(sizeof(struct SMBIOS_table_DA_substructure) == 6);

/* SMBIOS table type 0xDA = 218 */
struct SMBIOS_table_DA {
    struct SMBIOSHeader header;
    WORD SMBIOS_0xDA_io_port;
    BYTE SMBIOS_0xDA_io_port_value;
    BYTE field_7_fo_SMBIOS_0xDA;
    BYTE field_8_fo_SMBIOS_0xDA;
    BYTE field_9_fo_SMBIOS_0xDA;
    BYTE field_A_fo_SMBIOS_0xDA;
    struct SMBIOS_table_DA_substructure sub_data[];
};
STATIC_ASSERT(sizeof(struct SMBIOS_table_DA) == 0xb);

/**
 * Structure returned by GetSystemFirmwareTable('RSMB', 0, buffer, size)
 * https://docs.microsoft.com/en-us/windows/win32/api/sysinfoapi/nf-sysinfoapi-getsystemfirmwaretable
 */
struct RawSMBIOSData {
    BYTE Used20CallingMethod;
    BYTE SMBIOSMajorVersion;
    BYTE SMBIOSMinorVersion;
    BYTE DmiRevision;
    DWORD Length;
    /*BYTE SMBIOSTableData[];*/
    struct SMBIOSHeader SMBIOSTableData;
};
STATIC_ASSERT(sizeof(struct RawSMBIOSData) == 8 + sizeof(struct SMBIOSHeader));

/* Send buffer to I/O port seen by SMBIOS table 0xDA */
struct IO_PORT_ACTION_PARAMS_FROM_SBIOS_0xDA {
    DWORD field_0;
    DWORD field_4;
    DWORD field_8;
    DWORD field_c;
    DWORD field_10;
    DWORD field_14;
    DWORD field_18;
    DWORD field_1c;
    DWORD field_20;
};
STATIC_ASSERT(sizeof(struct IO_PORT_ACTION_PARAMS_FROM_SBIOS_0xDA) == 0x24);

/**
 * Allocation functions
 */
struct LIBC_MEM_FCTS {
    void *(*__cdecl malloc)(unsigned int size);
    void (*__cdecl free)(void *ptr);
    void *(*__cdecl ZeroMemory)(void *buffer, unsigned int size);
    void *(*__cdecl memcpy)(void *dst, const void *src, unsigned int size);
    int (*__cdecl memcmp)(const void *ptr1, const void *ptr2, unsigned int size);
};
#ifdef FOR_USER_SPACE_32
STATIC_ASSERT(sizeof(struct LIBC_MEM_FCTS) == 0x14);
#endif

/**
 * Common/BufferManager.c (tag 'MfuB')
 * Handle buffers of contiguous memory
 */
struct BufferBankEntry {
    DWORD phys_address_low32_start;
    DWORD phys_address_max_end; // End of the area which is really allocated
    DWORD phys_address_end_of_allocated; // The mapped memory gets allocated progressively?
    DWORD entry_id_in_bank; // max 64
    WORD number_allocated_blocks;
    WORD wHandle;
};
#ifdef FOR_USER_SPACE_32
STATIC_ASSERT(sizeof(struct BufferBankEntry) == 0x14);
#endif
struct BufferBank { // tag 'kBuB'
    struct LIST_HEADER list;
    DWORD tag__kBuB;
    struct BufferBankEntry entries[0x40];
    DWORD number_allocated__max_64;
};
#ifdef FOR_USER_SPACE_32
STATIC_ASSERT(sizeof(struct BufferBank) == 0x510);
#endif
struct BufferManager {
    DWORD (*__cdecl alloc_aligned)(struct BufferManager *self, DWORD size, int align_on_page_or_u32);
    BYTE (*__cdecl free)(struct BufferManager *self, DWORD addr);
    BYTE (*__cdecl read)(struct BufferManager *self, void *buffer, DWORD address, DWORD offset, DWORD size);
    BYTE (*__cdecl write)(struct BufferManager *self, DWORD address, DWORD offset, const void *buffer, DWORD size);
    // struct LIST_HEADER list_buffer_banks;
    struct BufferBank *list_buffer_banks_first;
    struct BufferBank *list_buffer_banks_last;
    // struct LIST_HEADER list_buffer_available_banks;
    struct BufferBank *list_buffer_available_banks_first;
    struct BufferBank *list_buffer_available_banks_last;
    struct DBUTIL_CONT_MEMORY_AFRW_HELPERS *alloc_funcs;
};
struct BufferManager_with_prelude {
    struct LIST_HEADER BufferManager_list;
    DWORD tag__MfuB;
    struct BufferManager obj;
};
#ifdef FOR_USER_SPACE_32
STATIC_ASSERT(sizeof(struct BufferManager_with_prelude) == 0x30);
#endif

/**
 * FlashUiWin.cpp (tag 'raBP')
 */
struct FlashUiWinProgressBar {
    void (*__cdecl delete)(struct FlashUiWinProgressBar *self);
    void (*__cdecl update)(struct FlashUiWinProgressBar *self, unsigned int action, void *buffer, int added, int maximal_position);
    const char *pszText;
    DWORD maximal_position;
    DWORD current_position;
    DWORD width_pixels;
    DWORD current_pixel_position;
    RECT rectangle_UI;
    RECT rectangle_filled;
    HWND hwndUiCanvas;
    HWND hwndUiProgress;
    HBRUSH hbrush;
    BYTE fHasUserInterface;
    BYTE _padding[3];
};
struct FlashUiWinProgressBar_with_prelude {
    DWORD tag;
    struct FlashUiWinProgressBar obj;
};
#ifdef FOR_USER_SPACE_32
STATIC_ASSERT(sizeof(struct FlashUiWinProgressBar_with_prelude) == 0x50);
#endif

/**
 * Common/EnhancedFileReader.c (tag 'dRnE')
 */
struct Reader_interface {
    void (*__cdecl delete)(struct Reader_interface *);
    int (*__cdecl initialize)(struct Reader_interface *self, const char *part);
    int (*__cdecl read)(struct Reader_interface *self, void *buffer, unsigned int size, unsigned int *size_read);
    int (*__cdecl stop)(struct Reader_interface *self);
};
struct EnhancedFileReader {
    int (*__cdecl delete)(struct EnhancedFileReader *self);
    int (*__cdecl open)(struct EnhancedFileReader *self, const char *szFileName);
    struct Reader_interface *(*__cdecl as_reader)(struct EnhancedFileReader *self);
    DWORD (*__cdecl get_file_size)(struct EnhancedFileReader *self);
    BYTE (*__cdecl set_position)(struct EnhancedFileReader *self, unsigned int offset, unsigned int size);
    void (*__cdecl set_position_to_read_all)(struct EnhancedFileReader *self);
    int (*__cdecl close)(struct EnhancedFileReader *self);
    struct Reader_interface reader_interface;
    FILE *file;
    DWORD file_size;
    DWORD current_file_position;
    DWORD current_offset_end; // current_offset + size
    DWORD current_offset;
    BYTE maybe_got_error;
    BYTE _padding[3];
};
struct EnhancedFileReader_with_prelude {
    DWORD tag;
    struct EnhancedFileReader obj;
};
#ifdef FOR_USER_SPACE_32
STATIC_ASSERT(sizeof(struct EnhancedFileReader_with_prelude) == 0x48);
#endif

/**
 * Common/InstrumentedReader.c (tag 'RSNI')
 */
struct InstrumentedReader {
    struct Reader_interface reader_interface;
    struct Reader_interface *inner_reader;
    void (*__cdecl pbar_update)(struct FlashUiWinProgressBar *self, unsigned int action, void *buffer, int added, int maximal_position);
    struct FlashUiWinProgressBar *pbar;
    DWORD total_size;
    BYTE unk_last;
    BYTE _padding[3];
};
struct InstrumentedReader_with_prelude {
    DWORD tag;
    struct InstrumentedReader obj;
};
#ifdef FOR_USER_SPACE_32
STATIC_ASSERT(sizeof(struct InstrumentedReader_with_prelude) == 0x28);
#endif

/**
 * Common/Decompressor.c (tag 'PMCD')
 */
struct Decompressor {
    struct Reader_interface reader_interface;
    struct InstrumentedReader *instrumented_reader; // "Input"
    void *pWorkArea; // "WorkArea", from malloc(0x2000)
    DWORD decompressor_state[14];
    BYTE unk_last;
    BYTE _padding[3];
};
struct Decompressor_with_prelude {
    DWORD tag;
    struct Decompressor obj;
};
#ifdef FOR_USER_SPACE_32
STATIC_ASSERT(sizeof(struct Decompressor_with_prelude) == 0x58);
#endif

/**
 * Common/MemoryStreamWriter.c (tag 'rWsM')
 */
struct Writer_interface {
    void *unknown;
    int (*__cdecl initialize)(struct Writer_interface *self, const char *part);
    int (*__cdecl write)(struct Writer_interface *self, const void *buffer, unsigned int size);
    int (*__cdecl stop)(struct Writer_interface *self);
};
struct MemoryStream_lists {
    struct LIST_HEADER list1;
    DWORD field_8;
    DWORD total_size;
    struct LIST_HEADER list3;
};
#ifdef FOR_USER_SPACE_32
STATIC_ASSERT(sizeof(struct MemoryStream_lists) == 0x18);
#endif
struct MemoryStreamWriter {
    void (*__cdecl delete)(struct MemoryStreamWriter *self);
    struct MemoryStream_lists *(*__cdecl get_written_memory)(struct MemoryStreamWriter *self);
    struct Writer_interface *(*__cdecl as_writer)(struct MemoryStreamWriter *self);
    struct Writer_interface writer_interface;
    struct MemoryStream_lists *pLists;
    struct BufferManager *buffer_mgr;
    BYTE is_not_stopped;
    BYTE _padding[3];
};
struct MemoryStreamWriter_with_prelude {
    DWORD tag;
    struct MemoryStreamWriter obj;
};
#ifdef FOR_USER_SPACE_32
STATIC_ASSERT(sizeof(struct MemoryStreamWriter_with_prelude) == 0x2c);
#endif

/**
 * Common/MemoryStreamReader.c (tag 'dRsM')
 */
struct MemoryStreamReader {
    void (*__cdecl delete)(struct MemoryStreamReader *self);
    struct MemoryStream_lists *(*__cdecl get_inner_memlist)(struct MemoryStreamReader *self);
    struct Reader_interface *(*__cdecl as_reader)(struct MemoryStreamReader *self);
    DWORD (*__cdecl get_size)(struct MemoryStreamReader *self);
    char (*__cdecl set_position_for_reader)(struct MemoryStreamReader *self, unsigned int position, unsigned int size);
    DWORD (*__cdecl read_this_memstream)(struct MemoryStreamReader *self, struct MemoryStream_lists *new_list);
    struct Reader_interface reader_interface;
    struct MemoryStream_lists *memstream_list;
    BYTE is_intialized_not_stopped;
    BYTE _padding[3];
};
struct MemoryStreamReader_with_prelude {
    DWORD tag;
    DWORD start_position_for_reader;
    DWORD end_position_for_reader;
    DWORD current_position_for_reader;
    struct MemoryStreamReader obj;
};
#ifdef FOR_USER_SPACE_32
STATIC_ASSERT(sizeof(struct MemoryStreamReader_with_prelude) == 0x40);
#endif

/**
 * Common/PfsReader.c (tag 'RsfP')
 */
struct PFS_SECTION_HEADER {
    BYTE guid[0x10];
    DWORD spec;
    DWORD version_spec;
    WORD version_content[4];
    DWORD unk1_zero;
    DWORD unk2_zero;
    DWORD section_size;
    DWORD rsa1_size;
    DWORD pmim_size;
    DWORD rsa2_size;
    DWORD crc_pmim;
    DWORD crc_rsa2;
    DWORD crc_section_data;
    DWORD crc_rsa1;
};
STATIC_ASSERT(sizeof(struct PFS_SECTION_HEADER) == 0x48);

struct PfsSection { /* tag 'EsfP' */
    DWORD tag__EsfP;
    struct LIST_HEADER section_list;
    struct PFS_SECTION_HEADER header;
    DWORD offset_section_data;
    DWORD offset_rsa1;
    DWORD offset_pmim;
    DWORD offset_rsa2;
};
#ifdef FOR_USER_SPACE_32
STATIC_ASSERT(sizeof(struct PfsSection) == 0x64);
#endif

/* Structure compatible with Reader_interface */
struct PfsReader_Interface {
    void (*__cdecl delete)(struct PfsReader_Interface *self);
    /* Section parts:
     * "D" for data
     * "d" for rsa1
     * "R" for pmim
     * "r" for rsa2
     * "A" for all
     */
    int (*__cdecl initialize_to_read_section_part)(struct PfsReader_Interface *self, const char *part);
    int (*__cdecl read_section_part)(struct PfsReader_Interface *self, void *buffer, DWORD size, DWORD *size_read);
    void (*__cdecl stop)(struct PfsReader_Interface *self);
};
struct PfsReader {
    void (*__cdecl delete)(struct PfsReader *self);
    int (*__cdecl load)(struct PfsReader *self, struct Reader_interface *reader_interface, const char *part_for_reader_init);
    DWORD (*__cdecl get_size_from_memstream_reader)(struct PfsReader *self);
    int (*__cdecl select_section_by_GUID)(struct PfsReader *self, const UUID *guid);
    int (*__cdecl iter_sections_begin)(struct PfsReader *self);
    int (*__cdecl iter_sections_next)(struct PfsReader *self);
    int (*__cdecl get_current_section_header)(struct PfsReader *self, struct PFS_SECTION_HEADER *section_header);
    struct Reader_interface *(*__cdecl as_section_reader)(struct PfsReader *self);
    struct PfsReader_Interface interface_funcs;
    struct BufferManager *buffer_mgr;
    struct MemoryStreamReader *memstream_reader;
    struct MemoryStream_lists *memstream_flash_payload;
    void *p_temp_buffer_0x2000;
    struct PfsSection *current_section;
    BYTE pfs_header_16bytes[16];
    BYTE pfs_footer_16bytes[16];
    BYTE has_memstream_reader;
    BYTE bool_field_26;
    BYTE bool_field_27;
    BYTE bool_field_28;
    BYTE bool_field_29;
    BYTE bool_field_30;
    WORD _padding;
};
struct PfsReader_with_prelude {
    DWORD tag__RsfP;
    struct LIST_HEADER section_list;
    struct PfsReader obj;
};
#ifdef FOR_USER_SPACE_32
STATIC_ASSERT(sizeof(struct PfsReader_with_prelude) == 0x78);
#endif

/**
 * Common/FlashPacketWriter.c (tag 'WkPF')
 */
struct FLASH_PACKET {
    DWORD magic_FPK;  // '.KPF' for "FPK." ("Flash Packet")
    DWORD position_tag; // "FST.", "MID." or "LST." (first, middle, last)?
    DWORD flashpkt_field_2;
    DWORD index; // 1 for first part
    DWORD unknow_0x1000; // maybe alignment or chunk size?
    DWORD header_size_0x40;
    DWORD data_size;
    DWORD crc32_of_data;
    DWORD xor_checksum_of_previous_fields;
    DWORD flashpkt_field_9_zero;
    DWORD flashpkt_field_10_zero;
    DWORD flashpkt_field_11_zero;
    DWORD flashpkt_field_12_zero;
    DWORD flashpkt_field_13_zero;
    DWORD flashpkt_field_14_zero;
    DWORD flashpkt_field_15_zero;
};
STATIC_ASSERT(sizeof(struct FLASH_PACKET) == 0x40);

struct FlashPacketWriter {
    /*
    void (*__cdecl delete)(struct FlashPacketWriter *self);
    int (*__cdecl initialize)(struct FlashPacketWriter *self);
    int (*__cdecl write_pktdata)(struct FlashPacketWriter *self, const void *buffer, DWORD size);
    int (*__cdecl stop__write_pkt_header)(struct FlashPacketWriter *self);
    */
    struct Writer_interface writer_interface;
    void *p_temp_buffer_0x2000;
    struct BufferManager *physmem_bufmgr; // Manager for physically-contiguous memory
    DWORD current_packet_phys_addr; // 64 bytes header + data
    DWORD current_packet_written_whole_size; // number of bytes written so far, including header
    DWORD current_packet_max_size__0x1000;  // 4096 bytes max
    DWORD current_packet_index__1_for_first;
    DWORD field_10;
    BYTE has_data;
    BYTE _padding[3];
};
struct FlashPacketWriter_with_prelude {
    DWORD tag__WkPF;
    struct FlashPacketWriter obj;
};
#ifdef FOR_USER_SPACE_32
STATIC_ASSERT(sizeof(struct FlashPacketWriter_with_prelude) == 0x34);
#endif

/**
 * Common/SmbiosTableReader.c (tag 'tBMS')
 */
struct SmbiosTableReader {
    DWORD (*__cdecl get_count_of_tables)(struct SmbiosTableReader *self);
    DWORD (*__cdecl get_max_size_of_a_table)(struct SmbiosTableReader *self);
    char (*__cdecl find_table_by_handle_type_idx)(struct SmbiosTableReader *self, WORD wTblHandle, BYTE tblType, BYTE tbl_index_for_type);
    struct Reader_interface *(*__cdecl get_reader_to_current_table)(struct SmbiosTableReader *self);
    char (*__cdecl read_current_table_into_buffer)(struct SmbiosTableReader *self, DWORD buffer_size, void *buffer, DWORD *size);
    char (*__cdecl get_SMBIOS_table_DA_info)(struct SmbiosTableReader *self, WORD kind, struct SMBIOS_table_DA_substructure *buffer);
    char (*__cdecl reset_position)(struct SmbiosTableReader *self);
};
struct SmbiosTableReader_with_prelude {
    DWORD tag__tBMS;
    struct LIBC_MEM_FCTS *pLibcMemFcts;
    struct SMBIOSHeader *pSMBIOS_table_data; // content at SMBIOSEntryPoint->TableAddress
    DWORD dwSMBIOS_table_length;
    struct MemoryStream_lists *memstream_to_SMBIOS_table;
    struct MemoryStreamReader *memstreamrdr_to_SMBIOS_table;
    DWORD count_of_tables;
    DWORD max_size_of_a_table;
    struct SMBIOSHeader **array_SMBIOS_tables_headers;
    BYTE *array_table_position_for_same_type; // Number of tables with the same type before this table, for each table
    DWORD current_tbl_index;
    struct SmbiosTableReader obj;
};
#ifdef FOR_USER_SPACE_32
STATIC_ASSERT(sizeof(struct SmbiosTableReader_with_prelude) == 0x48);
#endif


/**
 * Dell-specific command to query things related to BIOS, power and TPM (maybe SMI request?)
 * It is used to submit the BIOS password, for example, with:
 *     {0x3000A}
 *     {0x4000A, physaddr_BIOS_password_NUL_terminated}
 *
 * In order to check whether the state of the AC adapter and the level of the battery:
 *     [0x10008}
 *     [0x20008}
 *
 * It is also to query information about the TPM, with:
 *     {0x30007, 2}
 *     result:
 *        DellFW_out_result = 0 for success
 *        DellFW_field_6 = firmware version (0xAABBCCDD for A.B.C.D)
 *        (DellFW_field_7 >> 2) & 1 = is TPM owned?
 *        (DellFW_field_7 >> 8) & 0xF = 1 for TPM 1.2 or 2 for TPM 2.0
 *        DellFW_field_8 = number of remaining FW update
 */
struct DELL_FW_COMMAND_BUFFER {
    DWORD DellFW_in_command;
    DWORD DellFW_in_field_1;
    DWORD DellFW_in_field_2;
    DWORD DellFW_in_field_3;
    DWORD DellFW_in_field_4;
    DWORD DellFW_out_result;
    DWORD DellFW_out_field_6;
    DWORD DellFW_out_field_7;
    DWORD DellFW_out_field_8;
};
STATIC_ASSERT(sizeof(struct DELL_FW_COMMAND_BUFFER) == 0x24);

/* update program arguments */
struct UPDATE_PROGRAM_ARGS {
    BYTE fArg_S;
    BYTE fArg_f;
    BYTE fArgForceit;
    BYTE fArgNopause;
    BYTE fArgNoreboot;
    BYTE fArgR_or_S;
    BYTE fArg_S__bis;
    BYTE field_7;
    char *pszArg_l_LogPath;
    DWORD field_C;
    char *pszArg_p__BIOS_password;
    BYTE fArgHelp;
    BYTE fArg_verflashexe;
    WORD iFirstOptionalArg;
    char *pszArg_b__TPM_payload;
};
#ifdef FOR_USER_SPACE_32
STATIC_ASSERT(sizeof(struct UPDATE_PROGRAM_ARGS) == 0x1c);
#endif
