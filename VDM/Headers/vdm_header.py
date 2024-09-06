import ctypes
from ctypes import wintypes

class VDM:
    drv_handle = None

    @staticmethod
    def load_drv():
        VDM.drv_handle = ctypes.windll.kernel32.CreateFileW(
            "\\\\.\\RwDrv",
            wintypes.GENERIC_READ | wintypes.GENERIC_WRITE,
            wintypes.FILE_SHARE_READ | wintypes.FILE_SHARE_WRITE,
            None,
            wintypes.OPEN_EXISTING,
            wintypes.FILE_ATTRIBUTE_NORMAL,
            None
        )
        if VDM.drv_handle == wintypes.INVALID_HANDLE_VALUE:
            raise Exception("Failed to open driver")
        return VDM.drv_handle

    @staticmethod
    def unload_drv(drv_handle):
        if not ctypes.windll.kernel32.CloseHandle(drv_handle):
            return ctypes.windll.ntdll.STATUS_FAIL_CHECK

    @staticmethod
    def read_phys(addr, buffer, size):
        if not util.is_valid(addr):
            return False

        packet = {
            'in': addr,
            'size': size,
            'out': buffer
        }
        result = ctypes.windll.kernel32.DeviceIoControl(
            VDM.drv_handle,
            0x222808,
            ctypes.byref(packet),
            ctypes.sizeof(packet),
            ctypes.byref(packet),
            ctypes.sizeof(packet),
            None,
            None
        )
        return result

    @staticmethod
    def write_phys(addr, buffer, size):
        if not util.is_valid(addr):
            return False

        packet = {
            'in': addr,
            'size': size,
            'out': buffer
        }
        #0x22280C with good IOCTL code
        result = ctypes.windll.kernel32.DeviceIoControl(
            VDM.drv_handle,
            0x22280C,  #IOCTL write operation
            ctypes.byref(packet),
            ctypes.sizeof(packet),
            ctypes.byref(packet),
            ctypes.sizeof(packet),
            None,
            None
        )
        return result
