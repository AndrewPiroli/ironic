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
    def read(self, off=0, size=None):
        return self.__sock.send_guestread(self.paddr, self.size)
    def write(self, buf, off=0):
        assert len(buf) <= self.size
        self.__sock.send_guestwrite(self.paddr, buf)
        self.data_size = len(buf)