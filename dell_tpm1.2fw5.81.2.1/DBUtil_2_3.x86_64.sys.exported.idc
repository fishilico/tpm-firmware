// Export of DBUtil_2_3.x86_64.sys
// Import this in IDA 7.0+ using IDC and after importing structures.h
#include <idc.idc>
static main() {
    set_name(0x11000, "");
    set_name(0x11008, "real_driver_entry");
    SetType(0x11008, "NTSTATUS __fastcall x(PDRIVER_OBJECT DriverObject)");
    set_name(0x11170, "drvob_dispatch_function");
    SetType(0x11170, "__int64 __fastcall x(_DEVICE_OBJECT *devobj, _IRP *irp)");
    set_name(0x114f8, "input_io_port");
    SetType(0x114f8, "unsigned __int32 __fastcall x(unsigned __int16 port, unsigned int size)");
    set_name(0x11528, "output_io_port");
    SetType(0x11528, "char __fastcall x(unsigned __int16 port, unsigned int value, unsigned int size)");
    set_name(0x1155c, "identity_64bit_value_input");
    SetType(0x1155c, "__int64 __fastcall x(__int64 a1)");
    set_name(0x11574, "identity_64bit_value_output");
    SetType(0x11574, "unsigned __int64 __fastcall x(unsigned __int64 a1)");
    set_name(0x11590, "DeferredRoutine_smi_or_outport");
    SetType(0x11590, "KPRIORITY __fastcall x(__int64 a1, DBUTIL64_DEVICE_EXT *devext)");
    set_name(0x11630, "do_out_dx_al_with_registers_and_flush");
    SetType(0x11630, "void __fastcall x(DPC_SMI_PORT_REGISTERS *registers)");
    set_name(0x11657, "do_out_dx_ax_with_registers_and_flush");
    SetType(0x11657, "void __fastcall x(DPC_SMI_PORT_REGISTERS *registers)");
    set_name(0x1167f, "do_out_dx_eax_with_registers_and_flush");
    SetType(0x1167f, "void __fastcall x(DPC_SMI_PORT_REGISTERS *registers)");
    set_name(0x116a6, "restore_registers_and_flush_cache");
    SetType(0x116a6, "__int16 __usercall x@<ax>(__int64 a1@<rax>)");
    set_name(0x116c9, "wbinvd_io81_and_load_registers");
    SetType(0x116c9, "__int64 __usercall x@<rax>(DPC_SMI_PORT_REGISTERS *registers@<rbp>)");
    set_name(0x116ec, "do_int0xb2_with_registers");
    SetType(0x116ec, "void __fastcall x(DPC_SMI_PORT_REGISTERS *registers)");
    set_name(0x11730, "__security_check_cookie");
    SetType(0x11730, "void __fastcall x(ULONG_PTR cookie)");
    set_name(0x11758, "__report_gsfailure");
    SetType(0x11758, "void __fastcall __noreturn x(ULONG_PTR BugCheckParameter1)");
    set_name(0x11790, "memmove");
    SetType(0x11790, "void *__cdecl x(void *Dst, const void *Src, size_t Size)");
    set_name(0x11acc, "__GSHandlerCheckCommon");
    set_name(0x11b38, "__GSHandlerCheck");
    set_name(0x11b70, "memset");
    SetType(0x11b70, "void *__cdecl x(void *Dst, int Val, size_t Size)");
    set_name(0x15008, "do_io_port_input_or_output");
    SetType(0x15008, "unsigned int __fastcall x(DBUTIL64_DEVICE_EXT *devext, char fDoOtherOutPort, char fDoInput)");
    set_name(0x15100, "do_iomem_read_or_write");
    SetType(0x15100, "unsigned int __fastcall x(DBUTIL64_DEVICE_EXT *devext, char fDoRead)");
    set_name(0x151d4, "ioctl_0x9B0C1EC0_allocate_physical_mem");
    SetType(0x151d4, "unsigned int __fastcall x(DBUTIL64_DEVICE_EXT *devext)");
    set_name(0x15294, "do_memcpy_read_or_write");
    SetType(0x15294, "unsigned int __fastcall x(DBUTIL64_DEVICE_EXT *devext, char fDoRead)");
    set_name(0x16008, "DriverEntry");
    SetType(0x16008, "NTSTATUS __stdcall x(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)");
    print("Import OK :)");
    return 0;
}
