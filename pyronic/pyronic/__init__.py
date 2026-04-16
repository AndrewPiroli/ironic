from abc import ABC, abstractmethod
from struct import pack

class ToBuffer(ABC):
    @abstractmethod
    def to_buffer(self) -> bytes:
        raise NotImplementedError

class PatchRange(ToBuffer):
    def __init__(self, start: int, end: int, old: bytearray, new: bytearray, offset: int):
        self.start = start
        self.end = end
        self.old = old
        self.new = new
        self.offset = offset

    def to_buffer(self) -> bytes:
        ret = bytearray()
        ret += pack(">LLLLL", self.start, self.end, len(self.old), len(self.new), self.offset)
        ret += self.old
        ret += self.new
        return bytes(ret)

class MemHandle(object):
    """ A handle to some piece of guest memory """
    def __init__(self, sock, paddr, size):
        self.__sock = sock
        self.paddr = paddr
        self.size = size
    def read(self, size=None, off=0):
        if size == None:
            size = self.size

        return self.__sock.send_guestread(self.paddr + off, size)
    def read8(self, off=0):
        return self.__sock.send_ppc_read8(self.paddr + off)
    def read16(self, off=0):
        return self.__sock.send_ppc_read16(self.paddr + off)
    def read32(self, off=0):
        return self.__sock.send_ppc_read32(self.paddr + off)
    def write(self, buf, off=0):
        assert len(buf) <= self.size
        self.__sock.send_guestwrite(self.paddr + off, buf)
        self.data_size = len(buf)
    def write8(self, data, off=0):
        return self.__sock.send_ppc_write8(self.paddr + off, data)
    def write16(self, data, off=0):
        return self.__sock.send_ppc_write16(self.paddr + off, data)
    def write32(self, data, off=0):
        return self.__sock.send_ppc_write32(self.paddr + off, data)
