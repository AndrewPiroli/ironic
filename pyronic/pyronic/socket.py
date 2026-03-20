import socket
from hexdump import hexdump
from struct import pack, unpack
WRITE_LIMIT = 10000 - 12 # back/src/ppc.rs const BUF_LEN=100000 subtract message header 12 bytes

class IronicSocket(object):
    """ Representing some connection to the PPC HLE server. """
    IRONIC_READ        = 1
    IRONIC_WRITE       = 2
    IRONIC_MSG         = 3
    IRONIC_ACK         = 4
    IRONIC_MSGNORET    = 5
    IRONIC_PPC_READ8   = 6
    IRONIC_PPC_READ16  = 7
    IRONIC_PPC_READ32  = 8
    IRONIC_PPC_WRITE8  = 9
    IRONIC_PPC_WRITE16 = 10
    IRONIC_PPC_WRITE32 = 11
    IRONIC_QUIT        = 255

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

    def send_ppc_read8(self, paddr):
        """ Send a ppc_read8 command to the server """
        msg = bytearray()
        msg += pack("<LLL", self.IRONIC_PPC_READ8, paddr, 0)
        self.socket.send(msg)
        resp = self.socket.recv(1)
        assert len(resp) == 1
        return resp

    def send_ppc_read16(self, paddr):
        """ Send a ppc_read16 command to the server """
        msg = bytearray()
        msg += pack("<LLL", self.IRONIC_PPC_READ16, paddr, 0)
        self.socket.send(msg)
        resp = self.socket.recv(2)
        assert len(resp) == 2
        return resp

    def send_ppc_read32(self, paddr):
        """ Send a ppc_read32 command to the server """
        msg = bytearray()
        msg += pack("<LLL", self.IRONIC_PPC_READ32, paddr, 0)
        self.socket.send(msg)
        resp = self.socket.recv(4)
        assert len(resp) == 4
        return resp

    def send_ppc_write8(self, paddr, data):
        """ Send a ppc_write8 command to the server """
        msg = bytearray()
        msg += pack("<LLLB", self.IRONIC_PPC_WRITE8, paddr, 0, data)
        self.socket.send(msg)
        resp = self.socket.recv(2)
        assert resp.decode('utf-8') == "OK"

    def send_ppc_write16(self, paddr, data):
        """ Send a ppc_write16 command to the server """
        msg = bytearray()
        msg += pack("<LLLH", self.IRONIC_PPC_WRITE16, paddr, 0, data)
        self.socket.send(msg)
        resp = self.socket.recv(2)
        assert resp.decode('utf-8') == "OK"

    def send_ppc_write32(self, paddr, data):
        """ Send a ppc_write32 command to the server """
        msg = bytearray()
        msg += pack("<LLLL", self.IRONIC_PPC_WRITE32, paddr, 0, data)
        self.socket.send(msg)
        resp = self.socket.recv(2)
        assert resp.decode('utf-8') == "OK"


    def handle_large_guestwrite(self, paddr, buf):
        offset = 0
        while offset != len(buf):
            next_offset = min(len(buf), offset+WRITE_LIMIT)
            self.send_guestwrite(offset, buf[offset:next_offset])
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



