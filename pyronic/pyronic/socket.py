import socket
from struct import pack, unpack
from . import MemHandle
WRITE_LIMIT = 10000 - 12 # back/src/ppc.rs const BUF_LEN=100000 subtract message header 12 bytes

class IronicSocket(object):
    """ Representing some connection to the PPC HLE server. """
    IRONIC_READ    = 1
    IRONIC_WRITE   = 2
    IRONIC_MSG     = 3
    IRONIC_ACK     = 4
    IRONIC_MSGNORET= 5
    IRONIC_PATCH   = 14
    IRONIC_DISABLEPROT = 15
    IRONIC_QUIT    = 255

    def __init__(self, filename="/tmp/ironic-ppc.sock"):
        self.socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.socket.connect(filename)

    def close(self): 
        msg = bytearray()
        msg += pack("<LLL", self.IRONIC_QUIT, 0, 0)
        self.socket.send(msg)
        _ = self.socket.recv(2)
        self.socket.close()

    def send_guestread(self, paddr, size):
        """ Send a guest read command to the server """
        msg = bytearray()
        msg += pack("<LLL", self.IRONIC_READ, paddr, size)
        self.socket.send(msg)
        resp = self.socket.recv(size)
        assert len(resp) == size
        return resp

    def handle_large_guestwrite(self, paddr, buf):
        offset = 0
        while offset != len(buf):
            next_offset = min(len(buf), offset+WRITE_LIMIT)
            self.send_guestwrite(paddr + offset, buf[offset:next_offset])
            offset = next_offset
        pass

    def send_guestwrite(self, paddr, buf):
        """ Send a guest write command to the server """
        if len(buf) > WRITE_LIMIT:
            self.handle_large_guestwrite(paddr, buf)
            return
        msg = bytearray()
        msg += pack("<LLL", self.IRONIC_WRITE, paddr, len(buf))
        msg += buf
        self.socket.send(msg)
        resp = self.socket.recv(2)
        assert resp.decode('utf-8') == "OK"

    def send_ipcmsg(self, ptr):
        """ Send an IPC message command to the server """
        msg = bytearray()
        msg += pack("<LLL", self.IRONIC_MSG, ptr, 4)
        self.socket.send(msg)
        resp = self.socket.recv(2)
        assert resp.decode('utf-8') == "OK"
    def send_ipcmsg_noret(self, ptr):
        """ Send an IPC message command to the server """
        msg = bytearray()
        msg += pack("<LLL", self.IRONIC_MSGNORET, ptr, 4)
        self.socket.send(msg)
        resp = self.socket.recv(2)
        assert resp.decode('utf-8') == "OK"

    def send_patch_range(self, h: MemHandle) -> int:
        msg = bytearray()
        msg += pack("<LLL", self.IRONIC_PATCH, h.paddr, h.size)
        self.socket.send(msg)
        resp = self.socket.recv(2)
        return unpack("<H", resp)[0]

    def send_disableprot(self):
        msg = bytearray()
        msg += pack("<LLL", self.IRONIC_DISABLEPROT, 0, 0)
        self.socket.send(msg)
        resp = self.socket.recv(2)
        assert resp.decode('utf-8') == "OK"


    def recv_ipcmsg(self):
        """ Wait for the server to respond with a pointer to an IPC message """
        res_buf = self.socket.recv(4)
        res_ptr = unpack("<L", res_buf)[0]
        return res_ptr

    def send_ack(self):
        """ Send an ACK command to the server """
        msg = bytearray()
        msg += pack("<LLL", self.IRONIC_ACK, 0, 0)
        self.socket.send(msg)
        resp = self.socket.recv(2)
        assert resp.decode('utf-8') == "OK"



