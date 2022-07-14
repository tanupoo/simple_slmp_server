from socketserver import UDPServer, TCPServer
from socketserver import DatagramRequestHandler, StreamRequestHandler
import struct
import time

# XXX only 3E UDP, TCP
class SLMPServerProcess:

    def server_process(self, opt):
        def parse_command_ascii(data):
            d = struct.unpack("4s4s6s2s", data)
            return (int(d[0], 16), int(d[1], 16), d[2].decode(), int(d[3],16))

        def parse_command_binary(data):
            d = struct.unpack("<HHL", data)
            dev_code = d[2]>>24
            dev_num = d[2]&0xffffff
            return (d[0], d[1], dev_code, dev_num)

        # XXX 3E バイナリ 固定
        if opt.enable_ascii:
            self.hdr_len = 22
            self.cmd_len = 16
            self.read_num_field_len = 4
            self.parse_header_do = lambda d: [int(i,16) for i in struct.unpack("2s2s2s2s4s2s4s4s", d)]
            self.parse_command_do = parse_command_ascii
            self.parse_read_num = lambda d: int(d,16)
            self.make_response = lambda d: bytes([ord(i) for i in b"".join(d).hex()])
        else:
            self.hdr_len = 11
            self.cmd_len = 8
            self.read_num_field_len = 2
            self.parse_header_do = lambda d: struct.unpack("<BBBBHBHH", d)
            self.parse_command_do = parse_command_binary
            self.parse_read_num = lambda d: struct.unpack("<H", d)[0]
            self.make_response = lambda d: b"".join(d)

        #
        client_name = "{}[{}]".format(*self.client_address)
        print(f"connected from {client_name}")
        while True:
            buf = self.rfile.read(self.hdr_len)
            if len(buf) == 0:
                # connection terminated.
                break
            (t_ver, reserved, net_num, pc_num, io_num, drop_num, length, m_timer) = self.parse_header(buf)
            if length < self.cmd_len:
                print(f"ERROR: rest data size {length} is too short for {self.cmd_len}")
                # shutdown
                return
            # XXX should prevent from block
            buf = self.rfile.read(self.cmd_len)
            (cmd, sub_cmd, dev_code, dev_num) = self.parse_command(buf)
            # XXX how to know the number of size to read ??
            buf = self.rfile.read(self.read_num_field_len)
            read_num = self.parse_read_num(buf)
            print(f"read_num: {read_num}")
            self.response(b"\xd0\x00", net_num, pc_num, io_num, drop_num, cmd,
                          sub_cmd, dev_code, dev_num, read_num)

    def parse_header(self, data):
        (t_ver, reserved, net_num, pc_num, io_num, drop_num, length, m_timer) = self.parse_header_do(data)
        print(f"t_type: {t_ver:x}")
        print(f"reserved: {reserved:x}")
        print(f"network: {net_num:02x}")
        print(f"pc_num: {pc_num:02x}")
        print(f"io_num: {io_num:04x}")
        print(f"drop_num: {drop_num:02x}")
        print(f"length: {length:04x}")
        print(f"m_timer: {m_timer:02x}")
        return (t_ver, reserved, net_num, pc_num, io_num, drop_num, length,
                m_timer)

    def parse_command(self, data):
        (cmd, sub_cmd, dev_code, dev_num) = self.parse_command_do(data)
        print(f"cmd: {cmd:04x}")
        print(f"sub_cmd: {sub_cmd:04x}")
        print(f"dev_code: {dev_code:02x}")
        print(f"dev_num: {dev_num}")
        return (cmd, sub_cmd, dev_code, dev_num)

    def response(self, t_ver, net_num, pc_num, io_num, drop_num, cmd,
                 sub_cmd, dev_code, dev_num, read_num):
        # XXX A: depends on the size to be read.
        # "<B": read_num
        # "<L": read_num * 4
        if dev_code in [0xa8, 0xaf, 0xb4]:
            # D: 0xA8
            # W: 0xBF
            # R: 0xAF
            # "<H": read_num * 2
            read_size = 2
            pack_code = "<H"
        else:
            raise ValueError(f"Not supported dev_code={dev_code}")
        end_code = 0
        data_length = 2 + read_num * read_size
        ret_data = []
        ret_data.append(t_ver)
        ret_data.append(struct.pack("<BBHB", net_num, pc_num, io_num,
                                    drop_num))
        ret_data.append(struct.pack("<H", data_length))
        ret_data.append(struct.pack("<H", end_code))
        for i in range(read_num):
            ret_data.append(struct.pack(pack_code, int((i+time.time())%100)))
        self.wfile.write(self.make_response(ret_data))

class TCPHandler(StreamRequestHandler, SLMPServerProcess):

    def handle(self):
        self.server_process(opt)

class UDPHandler(DatagramRequestHandler, SLMPServerProcess):

    def handle(self):
        self.server_process(opt)

#
#
#
from argparse import ArgumentParser

ap = ArgumentParser()
ap.add_argument("-t", action="store_true", dest="enable_tcp",
                help="enable tcp mode.")
ap.add_argument("-4", action="store_true", dest="enable_4E",
                help="enable 4E mode.")
ap.add_argument("-a", action="store_true", dest="enable_ascii",
                help="enable 4E mode.")
ap.add_argument("-s", action="store", dest="server_addr",
                default="127.0.0.1",
                help="specify the server address.")
ap.add_argument("-p", action="store", dest="server_port",
                type=int, default=1025,
                help="specify the server address.")
opt = ap.parse_args()

if opt.enable_tcp:
    ServerClass = TCPServer
    HandlerClass = TCPHandler
else:
    ServerClass = UDPServer
    HandlerClass = UDPHandler

server = ServerClass((opt.server_addr, opt.server_port), HandlerClass)
print("listening on {} {}:{}".format("TCP" if opt.enable_tcp else "UDP",
                                  opt.server_addr, opt.server_port))
print("{} {}".format("4E" if opt.enable_4E else "3E",
                     "ASCII" if opt.enable_ascii else "BINARY"))
try:
    server.serve_forever()
except KeyboardInterrupt as e:
    print("Keyboard Interrupt")
except Exception as e:
    print("ERROR", e)
finally:
    server.server_close()
