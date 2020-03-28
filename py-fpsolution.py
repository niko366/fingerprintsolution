import os
import time
import sys
import traceback
import codecs
import datetime

from socket import AF_INET, SOCK_DGRAM, SOCK_STREAM, socket, timeout
from struct import pack, unpack
from builtins import input

pyfpPrompt = "niko366 ~# "
ip_fp = "niko366 ~# Masukkan ip   : "
port_fp = "niko366 ~# Masukkan port : "

# start const
USHRT_MAX = 65535
CMD_DB_RRQ = 7  # Read in some kind of data from the machine
CMD_USER_WRQ = 8  # Upload the user information (from PC to terminal).
CMD_USERTEMP_RRQ = 9  # Read some fingerprint template or some kind of data entirely
CMD_USERTEMP_WRQ = 10  # Upload some fingerprint template
CMD_OPTIONS_RRQ = 11  # Read in the machine some configuration parameter
CMD_OPTIONS_WRQ = 12  # Set machines configuration parameter
CMD_ATTLOG_RRQ = 13  # Read all attendance record
CMD_CLEAR_DATA = 14  # clear Data
CMD_CLEAR_ATTLOG = 15  # Clear attendance records
CMD_DELETE_USER = 18  # Delete some user
CMD_DELETE_USERTEMP = 19  # Delete some fingerprint template
CMD_CLEAR_ADMIN = 20  # Cancel the manager
CMD_USERGRP_RRQ = 21  # Read the user grouping
CMD_USERGRP_WRQ = 22  # Set users grouping
CMD_USERTZ_RRQ = 23  # Read the user Time Zone set
CMD_USERTZ_WRQ = 24  # Write the user Time Zone set
CMD_GRPTZ_RRQ = 25  # Read the group Time Zone set
CMD_GRPTZ_WRQ = 26  # Write the group Time Zone set
CMD_TZ_RRQ = 27  # Read Time Zone set
CMD_TZ_WRQ = 28  # Write the Time Zone
CMD_ULG_RRQ = 29  # Read unlocks combination
CMD_ULG_WRQ = 30  # write unlocks combination
CMD_UNLOCK = 31  # unlock
CMD_CLEAR_ACC = 32  # Restores Access Control set to the default condition.
CMD_CLEAR_OPLOG = 33  # Delete attendance machines all attendance record.
CMD_OPLOG_RRQ = 34  # Read manages the record
CMD_GET_FREE_SIZES = 50  # Obtain machines condition, like user recording number and so on
CMD_ENABLE_CLOCK = 57  # Ensure the machine to be at the normal work condition
CMD_STARTVERIFY = 60  # Ensure the machine to be at the authentication condition
CMD_STARTENROLL = 61  # Start to enroll some user, ensure the machine to be at the registration user condition
CMD_CANCELCAPTURE = 62  # Make the machine to be at the waiting order status, please refers to the CMD_STARTENROLL description.
CMD_STATE_RRQ = 64  # Gain the machine the condition
CMD_WRITE_LCD = 66  # Write LCD
CMD_CLEAR_LCD = 67  # Clear the LCD captions (clear screen).
CMD_GET_PINWIDTH = 69  # Obtain the length of user’s serial number
CMD_SMS_WRQ = 70  # Upload the short message.
CMD_SMS_RRQ = 71  # Download the short message
CMD_DELETE_SMS = 72  # Delete the short message
CMD_UDATA_WRQ = 73  # Set user’s short message
CMD_DELETE_UDATA = 74  # Delete user’s short message
CMD_DOORSTATE_RRQ = 75  # Obtain the door condition
CMD_WRITE_MIFARE = 76  # Write the Mifare card
CMD_EMPTY_MIFARE = 78  # Clear the Mifare card

CMD_GET_TIME = 201  # Obtain the machine time
CMD_SET_TIME = 202  # Set machines time
CMD_REG_EVENT = 500  # Register the event

CMD_CONNECT = 1000  # Connections requests
CMD_EXIT = 1001  # Disconnection requests
CMD_ENABLEDEVICE = 1002  # Ensure the machine to be at the normal work condition
CMD_DISABLEDEVICE = 1003  # Make the machine to be at the shut-down condition, generally demonstrates ‘in the work ...’on LCD
CMD_RESTART = 1004  # Restart the machine.
CMD_POWEROFF = 1005  # Shut-down power source
CMD_SLEEP = 1006  # Ensure the machine to be at the idle state.
CMD_RESUME = 1007  # Awakens the sleep machine (temporarily not to support)
CMD_CAPTUREFINGER = 1009  # Captures fingerprints picture
CMD_TEST_TEMP = 1011  # Test some fingerprint exists or does not
CMD_CAPTUREIMAGE = 1012  # Capture the entire image
CMD_REFRESHDATA = 1013  # Refresh the machine interior data
CMD_REFRESHOPTION = 1014  # Refresh the configuration parameter
CMD_TESTVOICE = 1017  # Play voice
CMD_GET_VERSION = 1100  # Obtain the firmware edition
CMD_CHANGE_SPEED = 1101  # Change transmission speed
CMD_AUTH = 1102  # Connections authorizations
CMD_PREPARE_DATA = 1500  # Prepares to transmit the data
CMD_DATA = 1501  # Transmit a data packet
CMD_FREE_DATA = 1502  # Clear machines opened buffer

CMD_ACK_OK = 2000  # Return value for order perform successfully
CMD_ACK_ERROR = 2001  # Return value for order perform failed
CMD_ACK_DATA = 2002  # Return data
CMD_ACK_RETRY = 2003  # * Regstered event occorred */
CMD_ACK_REPEAT = 2004  # Not available
CMD_ACK_UNAUTH = 2005  # Connection unauthorized

CMD_ACK_UNKNOWN = 0xffff  # Unkown order
CMD_ACK_ERROR_CMD = 0xfffd  # Order false
CMD_ACK_ERROR_INIT = 0xfffc  # /* Not Initializated */
CMD_ACK_ERROR_DATA = 0xfffb  # Not available

EF_ATTLOG = 1  # Be real-time to verify successfully
EF_FINGER = (1 << 1)  # be real–time to press fingerprint (be real time to return data type sign)
EF_ENROLLUSER = (1 << 2)  # Be real-time to enroll user
EF_ENROLLFINGER = (1 << 3)  # be real-time to enroll fingerprint
EF_BUTTON = (1 << 4)  # be real-time to press button
EF_UNLOCK = (1 << 5)  # be real-time to unlock
EF_VERIFY = (1 << 7)  # be real-time to verify fingerprint
EF_FPFTR = (1 << 8)  # be real-time capture fingerprint minutia
EF_ALARM = (1 << 9)  # Alarm signal

USER_DEFAULT = 0
USER_ENROLLER = 2
USER_MANAGER = 6
USER_ADMIN = 14

FCT_ATTLOG = 1
FCT_WORKCODE = 8
FCT_FINGERTMP = 2
FCT_OPLOG = 4
FCT_USER = 5
FCT_SMS = 6
FCT_UDATA = 7

MACHINE_PREPARE_DATA_1 = 20560  # 0x5050
MACHINE_PREPARE_DATA_2 = 32130  # 0x7282


class BasicException(Exception):
    pass


def clearScr():
    os.system('cls')  # windows
    # os.system('clear') #linux


def connecting():
    conn = None
    ip = "10.100.250.10"
    zk = FP(ip, port=4370, timeout=5, password=0, force_udp=False, ommit_ping=False)
    print('Menghubungkan ke mesin ...')
    conn = zk.connect()


def safe_cast(val, to_type, default=None):
    try:
        return to_type(val)
    except (ValueError, TypeError):
        return default


def make_commkey(key, session_id, ticks=50):
    key = int(key)
    session_id = int(session_id)
    k = 0
    for i in range(32):
        if (key & (1 << i)):
            k = (k << 1 | 1)
        else:
            k = k << 1
    k += session_id

    k = pack(b'I', k)
    k = unpack(b'BBBB', k)
    k = pack(
        b'BBBB',
        k[0] ^ ord('Z'),
        k[1] ^ ord('K'),
        k[2] ^ ord('S'),
        k[3] ^ ord('O'))
    k = unpack(b'HH', k)
    k = pack(b'HH', k[1], k[0])

    B = 0xff & ticks
    k = unpack(b'BBBB', k)
    k = pack(
        b'BBBB',
        k[0] ^ B,
        k[1] ^ B,
        B,
        k[3] ^ B)
    return k


class FP_helper(object):
    def __init__(self, ip, port=4370):
        self.address = (ip, port)
        self.ip = ip
        self.port = port

    def test_ping(self):
        import subprocess, platform
        ping_str = "-n 1" if platform.system().lower() == "windows" else "-c 1 -W 5"
        args = "ping " + " " + ping_str + " " + self.ip
        need_sh = False if platform.system().lower() == "windows" else True
        return subprocess.call(args,
                               stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE,
                               shell=need_sh) == 0

    def test_tcp(self):
        self.client = socket(AF_INET, SOCK_STREAM)
        self.client.settimeout(10)
        res = self.client.connect_ex(self.address)
        self.client.close()
        return res

    def test_udp(self):
        self.client = socket(AF_INET, SOCK_DGRAM)
        self.client.settimeout(10)


class FP(object):
    def __init__(self, ip, port=4370, timeout=60, password=0, force_udp=False, ommit_ping=False, verbose=False,
                 encoding='UTF-8'):
        User.encoding = encoding
        self.__address = (ip, port)
        self.__sock = socket(AF_INET, SOCK_DGRAM)
        self.__sock.settimeout(timeout)
        self.__timeout = timeout
        self.__password = password
        self.__session_id = 0
        self.__reply_id = USHRT_MAX - 1
        self.__data_recv = None
        self.__data = None

        self.is_connect = False
        self.is_enabled = True
        self.helper = FP_helper(ip, port)
        self.force_udp = force_udp
        self.ommit_ping = ommit_ping
        self.verbose = verbose
        self.encoding = encoding
        self.tcp = not force_udp
        self.users = 0
        self.fingers = 0
        self.records = 0
        self.dummy = 0
        self.cards = 0
        self.fingers_cap = 0
        self.users_cap = 0
        self.rec_cap = 0
        self.faces = 0
        self.faces_cap = 0
        self.fingers_av = 0
        self.users_av = 0
        self.rec_av = 0
        self.next_uid = 1
        self.next_user_id = '1'
        self.user_packet_size = 28  # default zk6
        self.end_live_capture = False

    def __nonzero__(self):
        """
        for boolean test
        """
        return self.is_connect

    def __create_socket(self):
        if self.tcp:
            self.__sock = socket(AF_INET, SOCK_STREAM)
            self.__sock.settimeout(self.__timeout)
            self.__sock.connect_ex(self.__address)
        else:
            self.__sock = socket(AF_INET, SOCK_DGRAM)
            self.__sock.settimeout(self.__timeout)

    def __create_tcp_top(self, packet):
        """
        witch the complete packet set top header
        """
        length = len(packet)
        top = pack('<HHI', MACHINE_PREPARE_DATA_1, MACHINE_PREPARE_DATA_2, length)
        return top + packet

    def __create_header(self, command, command_string, session_id, reply_id):

        buf = pack('<4H', command, 0, session_id, reply_id) + command_string
        buf = unpack('8B' + '%sB' % len(command_string), buf)
        checksum = unpack('H', self.__create_checksum(buf))[0]
        reply_id += 1
        if reply_id >= USHRT_MAX:
            reply_id -= USHRT_MAX

        buf = pack('<4H', command, checksum, session_id, reply_id)
        return buf + command_string

    def __create_socket(self):
        if self.tcp:
            self.__sock = socket(AF_INET, SOCK_STREAM)
            self.__sock.settimeout(self.__timeout)
            self.__sock.connect_ex(self.__address)
        else:
            self.__sock = socket(AF_INET, SOCK_DGRAM)
            self.__sock.settimeout(self.__timeout)

    def __create_checksum(self, p):

        l = len(p)
        checksum = 0
        while l > 1:
            checksum += unpack('H', pack('BB', p[0], p[1]))[0]
            p = p[2:]
            if checksum > USHRT_MAX:
                checksum -= USHRT_MAX
            l -= 2
        if l:
            checksum = checksum + p[-1]

        while checksum > USHRT_MAX:
            checksum -= USHRT_MAX

        checksum = ~checksum

        while checksum < 0:
            checksum += USHRT_MAX

        return pack('H', checksum)

    def __test_tcp_top(self, packet):
        """
        return size!
        """
        if len(packet) <= 8:
            return 0
        tcp_header = unpack('<HHI', packet[:8])
        if tcp_header[0] == MACHINE_PREPARE_DATA_1 and tcp_header[1] == MACHINE_PREPARE_DATA_2:
            return tcp_header[2]
        return 0

    def __send_command(self, command, command_string=b'', response_size=8):

        if command not in [CMD_CONNECT, CMD_AUTH] and not self.is_connect:
            raise FPErrorConnection("instance are not connected.")

        buf = self.__create_header(command, command_string, self.__session_id, self.__reply_id)
        try:
            if self.tcp:
                top = self.__create_tcp_top(buf)
                self.__sock.send(top)
                self.__tcp_data_recv = self.__sock.recv(response_size + 8)
                self.__tcp_length = self.__test_tcp_top(self.__tcp_data_recv)
                if self.__tcp_length == 0:
                    raise FPNetworkError("TCP packet invalid")
                self.__header = unpack('<4H', self.__tcp_data_recv[8:16])
                self.__data_recv = self.__tcp_data_recv[8:]
            else:
                self.__sock.sendto(buf, self.__address)
                self.__data_recv = self.__sock.recv(response_size)
                self.__header = unpack('<4H', self.__data_recv[:8])
        except Exception as e:
            raise FPNetworkError(str(e))

        self.__response = self.__header[0]
        self.__reply_id = self.__header[3]
        self.__data = self.__data_recv[8:]
        if self.__response in [CMD_ACK_OK, CMD_PREPARE_DATA, CMD_DATA]:
            return {
                'status': True,
                'code': self.__response
            }
        return {
            'status': False,
            'code': self.__response
        }

    def __ack_ok(self):
        """
        event ack ok
        """
        buf = self.__create_header(CMD_ACK_OK, b'', self.__session_id, USHRT_MAX - 1)
        try:
            if self.tcp:
                top = self.__create_tcp_top(buf)
                self.__sock.send(top)
            else:
                self.__sock.sendto(buf, self.__address)
        except Exception as e:
            raise FPNetworkError(str(e))

    def __get_data_size(self):
        response = self.__response
        if response == CMD_PREPARE_DATA:
            size = unpack('I', self.__data[:4])[0]
            return size
        else:
            return 0

    def __reverse_hex(self, hex):
        data = ''
        for i in reversed(range(len(hex) / 2)):
            data += hex[i * 2:(i * 2) + 2]
        return data

    def __decode_time(self, t):

        t = unpack("<I", t)[0]
        second = t % 60
        t = t // 60

        minute = t % 60
        t = t // 60

        hour = t % 24
        t = t // 24

        day = t % 31 + 1
        t = t // 31

        month = t % 12 + 1
        t = t // 12

        year = t + 2000

        d = datetime(year, month, day, hour, minute, second)

        return d

    def __decode_timehex(self, timehex):

        year, month, day, hour, minute, second = unpack("6B", timehex)
        year += 2000
        d = datetime(year, month, day, hour, minute, second)
        return d

    def __encode_time(self, t):

        d = (
                ((t.year % 100) * 12 * 31 + ((t.month - 1) * 31) + t.day - 1) *
                (24 * 60 * 60) + (t.hour * 60 + t.minute) * 60 + t.second
        )
        return d

    def connect(self):

        self.end_live_capture = False
        if not self.ommit_ping and not self.helper.test_ping():
            raise FPNetworkError("can't reach device (ping %s)" % self.__address[0])
        if not self.force_udp and self.helper.test_tcp() == 0:
            self.user_packet_size = 72
        self.__create_socket()
        self.__session_id = 0
        self.__reply_id = USHRT_MAX - 1
        cmd_response = self.__send_command(CMD_CONNECT)
        self.__session_id = self.__header[2]
        if cmd_response.get('code') == CMD_ACK_UNAUTH:
            if self.verbose: print("try auth")
            command_string = make_commkey(self.__password, self.__session_id)
            cmd_response = self.__send_command(CMD_AUTH, command_string)
        if cmd_response.get('status'):
            self.is_connect = True
            return self
        else:
            if cmd_response["code"] == CMD_ACK_UNAUTH:
                raise FPErrorResponse("Unauthenticated")
            if self.verbose: print("connect err response {} ".format(cmd_response["code"]))
            raise FPErrorResponse("Invalid response: Can't connect")

    def disconnect(self):

        cmd_response = self.__send_command(CMD_EXIT)
        if cmd_response.get('status'):
            self.is_connect = False
            if self.__sock:
                self.__sock.close()
            return True
        else:
            raise FPErrorResponse("can't disconnect")

    def enable_device(self):
        cmd_response = self.__send_command(CMD_ENABLEDEVICE)
        if cmd_response.get('status'):
            self.is_enabled = True
            return True
        else:
            raise FPErrorResponse("Can't enable device")

    def disable_device(self):

        cmd_response = self.__send_command(CMD_DISABLEDEVICE)
        if cmd_response.get('status'):
            self.is_enabled = False
            return True
        else:
            raise FPErrorResponse("Can't disable device")

    def get_firmware_version(self):

        cmd_response = self.__send_command(CMD_GET_VERSION, b'', 1024)
        if cmd_response.get('status'):
            firmware_version = self.__data.split(b'\x00')[0]
            return firmware_version.decode()
        else:
            raise FPErrorResponse("Can't read frimware version")

    def get_serialnumber(self):

        command = CMD_OPTIONS_RRQ
        command_string = b'~SerialNumber\x00'
        response_size = 1024
        cmd_response = self.__send_command(command, command_string, response_size)
        if cmd_response.get('status'):
            serialnumber = self.__data.split(b'=', 1)[-1].split(b'\x00')[0]
            serialnumber = serialnumber.replace(b'=', b'')
            return serialnumber.decode()  # string?
        else:
            raise FPErrorResponse("Can't read serial number")

    def get_platform(self):

        command = CMD_OPTIONS_RRQ
        command_string = b'~Platform\x00'
        response_size = 1024

        cmd_response = self.__send_command(command, command_string, response_size)
        if cmd_response.get('status'):
            platform = self.__data.split(b'=', 1)[-1].split(b'\x00')[0]
            platform = platform.replace(b'=', b'')
            return platform.decode()
        else:
            raise FPErrorResponse("Can't read platform name")

    def get_mac(self):

        command = CMD_OPTIONS_RRQ
        command_string = b'MAC\x00'
        response_size = 1024

        cmd_response = self.__send_command(command, command_string, response_size)
        if cmd_response.get('status'):
            mac = self.__data.split(b'=', 1)[-1].split(b'\x00')[0]
            return mac.decode()
        else:
            raise FPErrorResponse("can't read mac address")

    def get_device_name(self):

        command = CMD_OPTIONS_RRQ
        command_string = b'~DeviceName\x00'
        response_size = 1024

        cmd_response = self.__send_command(command, command_string, response_size)
        if cmd_response.get('status'):
            device = self.__data.split(b'=', 1)[-1].split(b'\x00')[0]
            return device.decode()
        else:
            return ""

    def get_face_version(self):

        command = CMD_OPTIONS_RRQ
        command_string = b'ZKFaceVersion\x00'
        response_size = 1024

        cmd_response = self.__send_command(command, command_string, response_size)
        if cmd_response.get('status'):
            response = self.__data.split(b'=', 1)[-1].split(b'\x00')[0]
            return safe_cast(response, int, 0) if response else 0
        else:
            return None

    def get_fp_version(self):

        command = CMD_OPTIONS_RRQ
        command_string = b'~ZKFPVersion\x00'
        response_size = 1024

        cmd_response = self.__send_command(command, command_string, response_size)
        if cmd_response.get('status'):
            response = self.__data.split(b'=', 1)[-1].split(b'\x00')[0]
            response = response.replace(b'=', b'')
            return safe_cast(response, int, 0) if response else 0
        else:
            raise FPErrorResponse("can't read fingerprint version")

    def _clear_error(self, command_string=b''):

        cmd_response = self.__send_command(CMD_ACK_ERROR, command_string, 1024)
        cmd_response = self.__send_command(CMD_ACK_UNKNOWN, command_string, 1024)
        cmd_response = self.__send_command(CMD_ACK_UNKNOWN, command_string, 1024)
        cmd_response = self.__send_command(CMD_ACK_UNKNOWN, command_string, 1024)

    def get_extend_fmt(self):

        command = CMD_OPTIONS_RRQ
        command_string = b'~ExtendFmt\x00'
        response_size = 1024

        cmd_response = self.__send_command(command, command_string, response_size)
        if cmd_response.get('status'):
            fmt = (self.__data.split(b'=', 1)[-1].split(b'\x00')[0])
            return safe_cast(fmt, int, 0) if fmt else 0
        else:
            self._clear_error(command_string)
            return None

    def get_user_extend_fmt(self):

        command = CMD_OPTIONS_RRQ
        command_string = b'~UserExtFmt\x00'
        response_size = 1024

        cmd_response = self.__send_command(command, command_string, response_size)
        if cmd_response.get('status'):
            fmt = (self.__data.split(b'=', 1)[-1].split(b'\x00')[0])
            return safe_cast(fmt, int, 0) if fmt else 0
        else:
            self._clear_error(command_string)
            return None

    def get_face_fun_on(self):

        command = CMD_OPTIONS_RRQ
        command_string = b'FaceFunOn\x00'
        response_size = 1024

        cmd_response = self.__send_command(command, command_string, response_size)
        if cmd_response.get('status'):
            response = (self.__data.split(b'=', 1)[-1].split(b'\x00')[0])
            return safe_cast(response, int, 0) if response else 0
        else:
            self._clear_error(command_string)
            return None

    def get_compat_old_firmware(self):

        command = CMD_OPTIONS_RRQ
        command_string = b'CompatOldFirmware\x00'
        response_size = 1024

        cmd_response = self.__send_command(command, command_string, response_size)
        if cmd_response.get('status'):
            response = (self.__data.split(b'=', 1)[-1].split(b'\x00')[0])
            return safe_cast(response, int, 0) if response else 0
        else:
            self._clear_error(command_string)
            return None

    def get_network_params(self):

        ip = self.__address[0]
        mask = b''
        gate = b''
        cmd_response = self.__send_command(CMD_OPTIONS_RRQ, b'IPAddress\x00', 1024)
        if cmd_response.get('status'):
            ip = (self.__data.split(b'=', 1)[-1].split(b'\x00')[0])
        cmd_response = self.__send_command(CMD_OPTIONS_RRQ, b'NetMask\x00', 1024)
        if cmd_response.get('status'):
            mask = (self.__data.split(b'=', 1)[-1].split(b'\x00')[0])
        cmd_response = self.__send_command(CMD_OPTIONS_RRQ, b'GATEIPAddress\x00', 1024)
        if cmd_response.get('status'):
            gate = (self.__data.split(b'=', 1)[-1].split(b'\x00')[0])
        return {'ip': ip.decode(), 'mask': mask.decode(), 'gateway': gate.decode()}

    def get_pin_width(self):

        command = CMD_GET_PINWIDTH
        command_string = b' P'
        response_size = 9
        cmd_response = self.__send_command(command, command_string, response_size)
        if cmd_response.get('status'):
            width = self.__data.split(b'\x00')[0]
            return bytearray(width)[0]
        else:
            raise FPErrorResponse("can0t get pin width")

    def free_data(self):

        command = CMD_FREE_DATA
        cmd_response = self.__send_command(command)
        if cmd_response.get('status'):
            return True
        else:
            raise FPErrorResponse("can't free data")

    def read_sizes(self):

        command = CMD_GET_FREE_SIZES
        response_size = 1024
        cmd_response = self.__send_command(command, b'', response_size)
        if cmd_response.get('status'):
            if self.verbose: print(codecs.encode(self.__data, 'hex'))
            size = len(self.__data)
            if len(self.__data) >= 80:
                fields = unpack('20i', self.__data[:80])
                self.users = fields[4]
                self.fingers = fields[6]
                self.records = fields[8]
                self.dummy = fields[10]  # ???
                self.cards = fields[12]
                self.fingers_cap = fields[14]
                self.users_cap = fields[15]
                self.rec_cap = fields[16]
                self.fingers_av = fields[17]
                self.users_av = fields[18]
                self.rec_av = fields[19]
                self.__data = self.__data[80:]
            if len(self.__data) >= 12:  # face info
                fields = unpack('3i', self.__data[:12])  # dirty hack! we need more information
                self.faces = fields[0]
                self.faces_cap = fields[2]
            return True
        else:
            raise FPErrorResponse("can't read sizes")

    def unlock(self, time=3):

        command = CMD_UNLOCK
        command_string = pack("I", int(time) * 10)
        cmd_response = self.__send_command(command, command_string)
        if cmd_response.get('status'):
            return True
        else:
            raise FPErrorResponse("Can't open door")

    def __str__(self):

        return "Informasi dari mesin fingerprint %s://%s:%s \nusers[%i]\t\t: %i/%i \nfingers\t\t\t: %i/%i \nrecords\t\t\t: %i/%i \nfaces\t\t\t: %i/%i \n" % (
            "tcp" if self.tcp else "udp", self.__address[0], self.__address[1],
            self.user_packet_size, self.users, self.users_cap,
            self.fingers, self.fingers_cap,
            self.records, self.rec_cap,
            self.faces, self.faces_cap
        )

    def restart(self):

        command = CMD_RESTART
        cmd_response = self.__send_command(command)
        if cmd_response.get('status'):
            self.is_connect = False
            self.next_uid = 1
            return True
        else:
            raise FPErrorResponse("can't restart device")

    def get_time(self):

        command = CMD_GET_TIME
        response_size = 1032
        cmd_response = self.__send_command(command, b'', response_size)
        if cmd_response.get('status'):
            return self.__decode_time(self.__data[:4])
        else:
            raise FPErrorResponse("can't get time")

    def set_time(self, timestamp):

        command = CMD_SET_TIME
        command_string = pack(b'I', self.__encode_time(timestamp))
        cmd_response = self.__send_command(command, command_string)
        if cmd_response.get('status'):
            return True
        else:
            raise FPErrorResponse("can't set time")

    def poweroff(self):

        command = CMD_POWEROFF
        command_string = b''
        response_size = 1032
        cmd_response = self.__send_command(command, command_string, response_size)
        if cmd_response.get('status'):
            self.is_connect = False
            self.next_uid = 1
            return True
        else:
            raise FPErrorResponse("can't poweroff")

    def refresh_data(self):
        command = CMD_REFRESHDATA
        cmd_response = self.__send_command(command)
        if cmd_response.get('status'):
            return True
        else:
            raise FPErrorResponse("can't refresh data")

    def test_voice(self, index=0):
        command = CMD_TESTVOICE
        command_string = pack("I", index)
        cmd_response = self.__send_command(command, command_string)
        if cmd_response.get('status'):
            return True
        else:
            return False

    def set_user(self, uid=None, name='', privilege=0, password='', group_id='', user_id='', card=0):

        command = CMD_USER_WRQ
        if uid is None:
            uid = self.next_uid
            if not user_id:
                user_id = self.next_user_id
        if not user_id:
            user_id = str(uid)
        # TODO: check what happens if name is missing...
        if privilege not in [USER_DEFAULT, USER_ADMIN]:
            privilege = USER_DEFAULT
        privilege = int(privilege)
        if self.user_packet_size == 28:
            if not group_id:
                group_id = 0
            try:
                command_string = pack('HB5s8sIxBHI', uid, privilege, password.encode(self.encoding, errors='ignore'),
                                      name.encode(self.encoding, errors='ignore'), card, int(group_id), 0, int(user_id))
            except Exception as e:
                if self.verbose: print("s_h Error pack: %s" % e)
                if self.verbose: print("Error pack: %s" % sys.exc_info()[0])
                raise FPErrorResponse("Can't pack user")
        else:
            name_pad = name.encode(self.encoding, errors='ignore').ljust(24, b'\x00')[:24]
            card_str = pack('i', int(card))[:4]
            command_string = pack('HB8s24s4sx7sx24s', uid, privilege, password.encode(self.encoding, errors='ignore'),
                                  name_pad, card_str, group_id.encode(), user_id.encode())
        response_size = 1024  # TODO check response?
        cmd_response = self.__send_command(command, command_string, response_size)
        if not cmd_response.get('status'):
            raise FPErrorResponse("Can't set user")
        self.refresh_data()
        if self.next_uid == uid:
            self.next_uid += 1  # better recalculate again
        if self.next_user_id == user_id:
            self.next_user_id = str(self.next_uid)

    def save_user_template(self, user, fingers=[]):
        if not isinstance(user, User):
            users = self.get_users()
            tusers = list(filter(lambda x: x.uid == user, users))
            if len(tusers) == 1:
                user = tusers[0]
            else:
                tusers = list(filter(lambda x: x.user_id == str(user), users))
                if len(tusers) == 1:
                    user = tusers[0]
                else:
                    raise FPErrorResponse("Can't find user")
        if isinstance(fingers, Finger):
            fingers = [fingers]
        fpack = b""
        table = b""
        fnum = 0x10
        tstart = 0
        for finger in fingers:
            tfp = finger.repack_only()
            table += pack("<bHbI", 2, user.uid, fnum + finger.fid, tstart)
            tstart += len(tfp)
            fpack += tfp
        if self.user_packet_size == 28:
            upack = user.repack29()
        else:
            upack = user.repack73()
        head = pack("III", len(upack), len(table), len(fpack))
        packet = head + upack + table + fpack
        self._send_with_buffer(packet)
        command = 110
        command_string = pack('<IHH', 12, 0, 8)
        cmd_response = self.__send_command(command, command_string)
        if not cmd_response.get('status'):
            raise FPErrorResponse("Can't save utemp")
        self.refresh_data()

    def _send_with_buffer(self, buffer):
        MAX_CHUNK = 1024
        size = len(buffer)
        self.free_data()
        command = CMD_PREPARE_DATA
        command_string = pack('I', size)
        cmd_response = self.__send_command(command, command_string)
        if not cmd_response.get('status'):
            raise FPErrorResponse("Can't prepare data")
        remain = size % MAX_CHUNK
        packets = (size - remain) // MAX_CHUNK
        start = 0
        for _wlk in range(packets):
            self.__send_chunk(buffer[start:start + MAX_CHUNK])
            start += MAX_CHUNK
        if remain:
            self.__send_chunk(buffer[start:start + remain])

    def __send_chunk(self, command_string):
        command = CMD_DATA
        cmd_response = self.__send_command(command, command_string)
        if cmd_response.get('status'):
            return True
        else:
            raise FPErrorResponse("Can't send chunk")

    def delete_user_template(self, uid=0, temp_id=0, user_id=''):
        if self.tcp and user_id:
            command = 134
            command_string = pack('<24sB', str(user_id), temp_id)
            cmd_response = self.__send_command(command, command_string)
            if cmd_response.get('status'):
                return True
            else:
                return False  # probably empty!
        if not uid:
            users = self.get_users()
            users = list(filter(lambda x: x.user_id == str(user_id), users))
            if not users:
                return False
            uid = users[0].uid
        command = CMD_DELETE_USERTEMP
        command_string = pack('hb', uid, temp_id)
        cmd_response = self.__send_command(command, command_string)
        if cmd_response.get('status'):
            return True
        else:
            return False

    def delete_user(self, uid=0, user_id=''):

        if not uid:
            users = self.get_users()
            users = list(filter(lambda x: x.user_id == str(user_id), users))
            if not users:
                return False
            uid = users[0].uid
        command = CMD_DELETE_USER
        command_string = pack('h', uid)
        cmd_response = self.__send_command(command, command_string)
        if not cmd_response.get('status'):
            raise FPErrorResponse("Can't delete user")
        self.refresh_data()
        if uid == (self.next_uid - 1):
            self.next_uid = uid

    def get_user_template(self, uid, temp_id=0, user_id=''):
        if not uid:
            users = self.get_users()
            users = list(filter(lambda x: x.user_id == str(user_id), users))
            if not users:
                return False
            uid = users[0].uid
        for _retries in range(3):
            command = 88  # command secret!!! GET_USER_TEMPLATE
            command_string = pack('hb', uid, temp_id)
            response_size = 1024 + 8
            cmd_response = self.__send_command(command, command_string, response_size)
            data = self.__recieve_chunk()
            if data is not None:
                resp = data[:-1]
                if resp[-6:] == b'\x00\x00\x00\x00\x00\x00':  # padding? bug?
                    resp = resp[:-6]
                return Finger(uid, temp_id, 1, resp)
            if self.verbose: print("retry get_user_template")
        else:
            if self.verbose: print("Can't read/find finger")
            return None

    def get_templates(self):

        self.read_sizes()
        if self.fingers == 0:
            return []
        templates = []
        templatedata, size = self.read_with_buffer(CMD_DB_RRQ, FCT_FINGERTMP)
        if size < 4:
            if self.verbose: print("WRN: no user data")
            return []
        total_size = unpack('i', templatedata[0:4])[0]
        if self.verbose: print("get template total size {}, size {} len {}".format(total_size, size, len(templatedata)))
        templatedata = templatedata[4:]
        while total_size:
            size, uid, fid, valid = unpack('HHbb', templatedata[:6])
            template = unpack("%is" % (size - 6), templatedata[6:size])[0]
            finger = Finger(uid, fid, valid, template)
            if self.verbose: print(finger)
            templates.append(finger)
            templatedata = templatedata[size:]
            total_size -= size
        return templates

    def get_users(self):

        self.read_sizes()
        if self.users == 0:
            self.next_uid = 1
            self.next_user_id = '1'
            return []
        users = []
        max_uid = 0
        userdata, size = self.read_with_buffer(CMD_USERTEMP_RRQ, FCT_USER)
        if self.verbose: print("user size {} (= {})".format(size, len(userdata)))
        if size <= 4:
            print("WRN: missing user data")
            return []
        total_size = unpack("I", userdata[:4])[0]
        self.user_packet_size = total_size / self.users
        if not self.user_packet_size in [28, 72]:
            if self.verbose: print("WRN packet size would be  %i" % self.user_packet_size)
        userdata = userdata[4:]
        if self.user_packet_size == 28:
            while len(userdata) >= 28:
                uid, privilege, password, name, card, group_id, timezone, user_id = unpack('<HB5s8sIxBhI',
                                                                                           userdata.ljust(28, b'\x00')[
                                                                                           :28])
                if uid > max_uid: max_uid = uid
                password = (password.split(b'\x00')[0]).decode(self.encoding, errors='ignore')
                name = (name.split(b'\x00')[0]).decode(self.encoding, errors='ignore').strip()
                group_id = str(group_id)
                user_id = str(user_id)
                # TODO: check card value and find in ver8
                if not name:
                    name = "NN-%s" % user_id
                user = User(uid, name, privilege, password, group_id, user_id, card)
                users.append(user)
                if self.verbose: print("[6]user:", uid, privilege, password, name, card, group_id, timezone, user_id)
                userdata = userdata[28:]
        else:
            while len(userdata) >= 72:
                uid, privilege, password, name, card, group_id, user_id = unpack('<HB8s24sIx7sx24s',
                                                                                 userdata.ljust(72, b'\x00')[:72])
                password = (password.split(b'\x00')[0]).decode(self.encoding, errors='ignore')
                name = (name.split(b'\x00')[0]).decode(self.encoding, errors='ignore').strip()
                group_id = (group_id.split(b'\x00')[0]).decode(self.encoding, errors='ignore').strip()
                user_id = (user_id.split(b'\x00')[0]).decode(self.encoding, errors='ignore')
                if uid > max_uid: max_uid = uid
                if not name:
                    name = "NN-%s" % user_id
                user = User(uid, name, privilege, password, group_id, user_id, card)
                users.append(user)
                userdata = userdata[72:]
        max_uid += 1
        self.next_uid = max_uid
        self.next_user_id = str(max_uid)
        while True:
            if any(u for u in users if u.user_id == self.next_user_id):
                max_uid += 1
                self.next_user_id = str(max_uid)
            else:
                break
        return users

    def cancel_capture(self):

        command = CMD_CANCELCAPTURE
        cmd_response = self.__send_command(command)
        return bool(cmd_response.get('status'))

    def verify_user(self):
        command = CMD_STARTVERIFY
        cmd_response = self.__send_command(command)
        if cmd_response.get('status'):
            return True
        else:
            raise FPErrorResponse("Cant Verify")

    def reg_event(self, flags):

        command = CMD_REG_EVENT
        command_string = pack("I", flags)
        cmd_response = self.__send_command(command, command_string)
        if not cmd_response.get('status'):
            raise FPErrorResponse("cant' reg events %i" % flags)

    def set_sdk_build_1(self):
        command = CMD_OPTIONS_WRQ
        command_string = b"SDKBuild=1"
        cmd_response = self.__send_command(command, command_string)
        if not cmd_response.get('status'):
            return False
        return True

    def enroll_user(self, uid=0, temp_id=0, user_id=''):
        command = CMD_STARTENROLL
        done = False
        if not user_id:
            users = self.get_users()
            users = list(filter(lambda x: x.uid == uid, users))
            if len(users) >= 1:
                user_id = users[0].user_id
            else:
                return False
        if self.tcp:
            command_string = pack('<24sbb', str(user_id).encode(), temp_id, 1)
        else:
            command_string = pack('<Ib', int(user_id), temp_id)
        self.cancel_capture()
        cmd_response = self.__send_command(command, command_string)
        if not cmd_response.get('status'):
            raise FPErrorResponse("Cant Enroll user #%i [%i]" % (uid, temp_id))
        self.__sock.settimeout(60)
        attempts = 3
        while attempts:
            if self.verbose: print("A:%i esperando primer regevent" % attempts)
            data_recv = self.__sock.recv(1032)
            self.__ack_ok()
            if self.verbose: print(codecs.encode(data_recv, 'hex'))
            if self.tcp:
                if len(data_recv) > 16:
                    res = unpack("H", data_recv.ljust(24, b"\x00")[16:18])[0]
                    if self.verbose: print("res %i" % res)
                    if res == 0 or res == 6 or res == 4:
                        if self.verbose: print("posible timeout  o reg Fallido")
                        break
            else:
                if len(data_recv) > 8:
                    res = unpack("H", data_recv.ljust(16, b"\x00")[8:10])[0]
                    if self.verbose: print("res %i" % res)
                    if res == 6 or res == 4:
                        if self.verbose: print("posible timeout")
                        break
            if self.verbose: print("A:%i esperando 2do regevent" % attempts)
            data_recv = self.__sock.recv(1032)
            self.__ack_ok()
            if self.verbose: print(codecs.encode(data_recv, 'hex'))
            if self.tcp:
                if len(data_recv) > 8:
                    res = unpack("H", data_recv.ljust(24, b"\x00")[16:18])[0]
                    if self.verbose: print("res %i" % res)
                    if res == 6 or res == 4:
                        if self.verbose: print("posible timeout  o reg Fallido")
                        break
                    elif res == 0x64:
                        if self.verbose: print("ok, continue?")
                        attempts -= 1
            else:
                if len(data_recv) > 8:
                    res = unpack("H", data_recv.ljust(16, b"\x00")[8:10])[0]
                    if self.verbose: print("res %i" % res)
                    if res == 6 or res == 4:
                        if self.verbose: print("posible timeout  o reg Fallido")
                        break
                    elif res == 0x64:
                        if self.verbose: print("ok, continue?")
                        attempts -= 1
        if attempts == 0:
            data_recv = self.__sock.recv(1032)
            self.__ack_ok()
            if self.verbose: print(codecs.encode(data_recv, 'hex'))
            if self.tcp:
                res = unpack("H", data_recv.ljust(24, b"\x00")[16:18])[0]
            else:
                res = unpack("H", data_recv.ljust(16, b"\x00")[8:10])[0]
            if self.verbose: print("res %i" % res)
            if res == 5:
                if self.verbose: print("finger duplicate")
            if res == 6 or res == 4:
                if self.verbose: print("posible timeout")
            if res == 0:
                size = unpack("H", data_recv.ljust(16, b"\x00")[10:12])[0]
                pos = unpack("H", data_recv.ljust(16, b"\x00")[12:14])[0]
                if self.verbose: print("enroll ok", size, pos)
                done = True
        self.__sock.settimeout(self.__timeout)
        self.reg_event(0)  # TODO: test
        self.cancel_capture()
        self.verify_user()
        return done

    def live_capture(self, new_timeout=10):
        was_enabled = self.is_enabled
        users = self.get_users()
        self.cancel_capture()
        self.verify_user()
        if not self.is_enabled:
            self.enable_device()
        if self.verbose: print("start live_capture")
        self.reg_event(EF_ATTLOG)
        self.__sock.settimeout(new_timeout)
        self.end_live_capture = False
        while not self.end_live_capture:
            try:
                if self.verbose: print("esperando event")
                data_recv = self.__sock.recv(1032)
                self.__ack_ok()
                if self.tcp:
                    size = unpack('<HHI', data_recv[:8])[2]
                    header = unpack('HHHH', data_recv[8:16])
                    data = data_recv[16:]
                else:
                    size = len(data_recv)
                    header = unpack('<4H', data_recv[:8])
                    data = data_recv[8:]
                if not header[0] == CMD_REG_EVENT:
                    if self.verbose: print("not event! %x" % header[0])
                    continue
                if not len(data):
                    if self.verbose: print("empty")
                    continue
                while len(data) >= 12:
                    if len(data) == 12:
                        user_id, status, punch, timehex = unpack('<IBB6s', data)
                        data = data[12:]
                    elif len(data) == 32:
                        user_id, status, punch, timehex = unpack('<24sBB6s', data[:32])
                        data = data[32:]
                    elif len(data) == 36:
                        user_id, status, punch, timehex, _other = unpack('<24sBB6s4s', data[:36])
                        data = data[36:]
                    elif len(data) >= 52:
                        user_id, status, punch, timehex, _other = unpack('<24sBB6s20s', data[:52])
                        data = data[52:]
                    if isinstance(user_id, int):
                        user_id = str(user_id)
                    else:
                        user_id = (user_id.split(b'\x00')[0]).decode(errors='ignore')
                    timestamp = self.__decode_timehex(timehex)
                    tuser = list(filter(lambda x: x.user_id == user_id, users))
                    if not tuser:
                        uid = int(user_id)
                    else:
                        uid = tuser[0].uid
                    yield Attendance(user_id, timestamp, status, punch, uid)
            except timeout:
                if self.verbose: print("time out")
                yield None  # return to keep watching
            except (KeyboardInterrupt, SystemExit):
                if self.verbose: print("break")
                break
        if self.verbose: print("exit gracefully")
        self.__sock.settimeout(self.__timeout)
        self.reg_event(0)
        if not was_enabled:
            self.disable_device()

    def clear_data(self):
        command = CMD_CLEAR_DATA
        command_string = ''
        cmd_response = self.__send_command(command, command_string)
        if cmd_response.get('status'):
            self.is_connect = False
            self.next_uid = 1
            return True
        else:
            raise FPErrorResponse("can't clear data")

    def __recieve_tcp_data(self, data_recv, size):
        data = []
        tcp_length = self.__test_tcp_top(data_recv)
        if self.verbose: print("tcp_length {}, size {}".format(tcp_length, size))
        if tcp_length <= 0:
            if self.verbose: print("Incorrect tcp packet")
            return None, b""
        if (tcp_length - 8) < size:
            if self.verbose: print("tcp length too small... retrying")
            resp, bh = self.__recieve_tcp_data(data_recv, tcp_length - 8)
            data.append(resp)
            size -= len(resp)
            if self.verbose: print("new tcp DATA packet to fill misssing {}".format(size))
            data_recv = bh + self.__sock.recv(size + 16)
            if self.verbose: print("new tcp DATA starting with {} bytes".format(len(data_recv)))
            resp, bh = self.__recieve_tcp_data(data_recv, size)
            data.append(resp)
            if self.verbose: print("for misssing {} recieved {} with extra {}".format(size, len(resp), len(bh)))
            return b''.join(data), bh
        recieved = len(data_recv)
        if self.verbose: print("recieved {}, size {}".format(recieved, size))
        response = unpack('HHHH', data_recv[8:16])[0]
        if recieved >= (size + 32):
            if response == CMD_DATA:
                resp = data_recv[16: size + 16]
                if self.verbose: print("resp complete len {}".format(len(resp)))
                return resp, data_recv[size + 16:]
            else:
                if self.verbose: print("incorrect response!!! {}".format(response))
                return None, b""
        else:
            if self.verbose: print("try DATA incomplete (actual valid {})".format(recieved - 16))
            data.append(data_recv[16: size + 16])
            size -= recieved - 16
            broken_header = b""
            if size < 0:
                broken_header = data_recv[size:]
                if self.verbose: print("broken", (broken_header).encode('hex'))
            if size > 0:
                data_recv = self.__recieve_raw_data(size)
                data.append(data_recv)
            return b''.join(data), broken_header

    def __recieve_raw_data(self, size):
        """ partial data ? """
        data = []
        if self.verbose: print("expecting {} bytes raw data".format(size))
        while size > 0:
            data_recv = self.__sock.recv(size)
            recieved = len(data_recv)
            if self.verbose: print("partial recv {}".format(recieved))
            if recieved < 100 and self.verbose: print("   recv {}".format(codecs.encode(data_recv, 'hex')))
            data.append(data_recv)
            size -= recieved
            if self.verbose: print("still need {}".format(size))
        return b''.join(data)

    def __recieve_chunk(self):
        """ recieve a chunk """
        if self.__response == CMD_DATA:
            if self.tcp:
                if self.verbose: print(
                    "_rc_DATA! is {} bytes, tcp length is {}".format(len(self.__data), self.__tcp_length))
                if len(self.__data) < (self.__tcp_length - 8):
                    need = (self.__tcp_length - 8) - len(self.__data)
                    if self.verbose: print("need more data: {}".format(need))
                    more_data = self.__recieve_raw_data(need)
                    return b''.join([self.__data, more_data])
                else:
                    if self.verbose: print("Enough data")
                    return self.__data
            else:
                if self.verbose: print("_rc len is {}".format(len(self.__data)))
                return self.__data
        elif self.__response == CMD_PREPARE_DATA:
            data = []
            size = self.__get_data_size()
            if self.verbose: print("recieve chunk: prepare data size is {}".format(size))
            if self.tcp:
                if len(self.__data) >= (8 + size):
                    data_recv = self.__data[8:]
                else:
                    data_recv = self.__data[8:] + self.__sock.recv(size + 32)
                resp, broken_header = self.__recieve_tcp_data(data_recv, size)
                data.append(resp)
                # get CMD_ACK_OK
                if len(broken_header) < 16:
                    data_recv = broken_header + self.__sock.recv(16)
                else:
                    data_recv = broken_header
                if len(data_recv) < 16:
                    print("trying to complete broken ACK %s /16" % len(data_recv))
                    if self.verbose: print(data_recv.encode('hex'))
                    data_recv += self.__sock.recv(16 - len(data_recv))  # TODO: CHECK HERE_!
                if not self.__test_tcp_top(data_recv):
                    if self.verbose: print("invalid chunk tcp ACK OK")
                    return None
                response = unpack('HHHH', data_recv[8:16])[0]
                if response == CMD_ACK_OK:
                    if self.verbose: print("chunk tcp ACK OK!")
                    return b''.join(data)
                if self.verbose: print("bad response %s" % data_recv)
                if self.verbose: print(codecs.encode(data, 'hex'))
                return None

                return resp
            while True:
                data_recv = self.__sock.recv(1024 + 8)
                response = unpack('<4H', data_recv[:8])[0]
                if self.verbose: print("# packet response is: {}".format(response))
                if response == CMD_DATA:
                    data.append(data_recv[8:])
                    size -= 1024
                elif response == CMD_ACK_OK:
                    break
                else:
                    if self.verbose: print("broken!")
                    break
                if self.verbose: print("still needs %s" % size)
            return b''.join(data)
        else:
            if self.verbose: print("invalid response %s" % self.__response)
            return None

    def __read_chunk(self, start, size):
        for _retries in range(3):
            command = 1504
            command_string = pack('<ii', start, size)
            if self.tcp:
                response_size = size + 32
            else:
                response_size = 1024 + 8
            cmd_response = self.__send_command(command, command_string, response_size)
            data = self.__recieve_chunk()
            if data is not None:
                return data
        else:
            raise FPErrorResponse("can't read chunk %i:[%i]" % (start, size))

    def read_with_buffer(self, command, fct=0, ext=0):
        if self.tcp:
            MAX_CHUNK = 0xFFc0
        else:
            MAX_CHUNK = 16 * 1024
        command_string = pack('<bhii', 1, command, fct, ext)
        if self.verbose: print("rwb cs", command_string)
        response_size = 1024
        data = []
        start = 0
        cmd_response = self.__send_command(1503, command_string, response_size)
        if not cmd_response.get('status'):
            raise FPErrorResponse("RWB Not supported")
        if cmd_response['code'] == CMD_DATA:
            if self.tcp:
                if self.verbose: print(
                    "DATA! is {} bytes, tcp length is {}".format(len(self.__data), self.__tcp_length))
                if len(self.__data) < (self.__tcp_length - 8):
                    need = (self.__tcp_length - 8) - len(self.__data)
                    if self.verbose: print("need more data: {}".format(need))
                    more_data = self.__recieve_raw_data(need)
                    return b''.join([self.__data, more_data]), len(self.__data) + len(more_data)
                else:
                    if self.verbose: print("Enough data")
                    size = len(self.__data)
                    return self.__data, size
            else:
                size = len(self.__data)
                return self.__data, size
        size = unpack('I', self.__data[1:5])[0]
        if self.verbose: print("size fill be %i" % size)
        remain = size % MAX_CHUNK
        packets = (size - remain) // MAX_CHUNK  # should be size /16k
        if self.verbose: print(
            "rwb: #{} packets of max {} bytes, and extra {} bytes remain".format(packets, MAX_CHUNK, remain))
        for _wlk in range(packets):
            data.append(self.__read_chunk(start, MAX_CHUNK))
            start += MAX_CHUNK
        if remain:
            data.append(self.__read_chunk(start, remain))
            start += remain
        self.free_data()
        if self.verbose: print("_read w/chunk %i bytes" % start)
        return b''.join(data), start

    def get_attendance(self):
        self.read_sizes()
        if self.records == 0:
            return []
        users = self.get_users()
        if self.verbose: print(users)
        attendances = []
        attendance_data, size = self.read_with_buffer(CMD_ATTLOG_RRQ)
        if size < 4:
            if self.verbose: print("WRN: no attendance data")
            return []
        total_size = unpack("I", attendance_data[:4])[0]
        record_size = total_size / self.records
        if self.verbose: print("record_size is ", record_size)
        attendance_data = attendance_data[4:]
        if record_size == 8:
            while len(attendance_data) >= 8:
                uid, status, timestamp, punch = unpack('HB4sB', attendance_data.ljust(8, b'\x00')[:8])
                if self.verbose: print(codecs.encode(attendance_data[:8], 'hex'))
                attendance_data = attendance_data[8:]
                tuser = list(filter(lambda x: x.uid == uid, users))
                if not tuser:
                    user_id = str(uid)
                else:
                    user_id = tuser[0].user_id
                timestamp = self.__decode_time(timestamp)
                attendance = Attendance(user_id, timestamp, status, punch, uid)
                attendances.append(attendance)
        elif record_size == 16:
            while len(attendance_data) >= 16:
                user_id, timestamp, status, punch, reserved, workcode = unpack('<I4sBB2sI',
                                                                               attendance_data.ljust(16, b'\x00')[:16])
                user_id = str(user_id)
                if self.verbose: print(codecs.encode(attendance_data[:16], 'hex'))
                attendance_data = attendance_data[16:]
                tuser = list(filter(lambda x: x.user_id == user_id, users))
                if not tuser:
                    if self.verbose: print("no uid {}", user_id)
                    uid = str(user_id)
                    tuser = list(filter(lambda x: x.uid == user_id, users))
                    if not tuser:
                        uid = str(user_id)
                    else:
                        uid = tuser[0].uid
                        user_id = tuser[0].user_id
                else:
                    uid = tuser[0].uid
                timestamp = self.__decode_time(timestamp)
                attendance = Attendance(user_id, timestamp, status, punch, uid)
                attendances.append(attendance)
        else:
            while len(attendance_data) >= 40:
                uid, user_id, status, timestamp, punch, space = unpack('<H24sB4sB8s',
                                                                       attendance_data.ljust(40, b'\x00')[:40])
                if self.verbose: print(codecs.encode(attendance_data[:40], 'hex'))
                user_id = (user_id.split(b'\x00')[0]).decode(errors='ignore')
                timestamp = self.__decode_time(timestamp)

                attendance = Attendance(user_id, timestamp, status, punch, uid)
                attendances.append(attendance)
                attendance_data = attendance_data[40:]
        return attendances

    def clear_attendance(self):
        command = CMD_CLEAR_ATTLOG
        cmd_response = self.__send_command(command)
        if cmd_response.get('status'):
            return True
        else:
            raise FPErrorResponse("Can't clear response")


class User(object):
    encoding = 'UTF-8'

    def __init__(self, uid, name, privilege, password='', group_id='', user_id='', card=0):
        self.uid = uid
        self.name = str(name)
        self.privilege = privilege
        self.password = str(password)
        self.group_id = str(group_id)
        self.user_id = user_id
        self.card = int(card)  # 64 int to 40 bit int

    @staticmethod
    def json_unpack(json):
        # validate?
        return User(
            uid=json['uid'],
            name=json['name'],
            privilege=json['privilege'],
            password=json['password'],
            group_id=json['group_id'],
            user_id=json['user_id'],
            card=json['card']
        )

    def repack29(self):  # with 02 for zk6 (size 29)
        return pack("<BHB5s8sIxBhI", 2, self.uid, self.privilege, self.password.encode(User.encoding, errors='ignore'),
                    self.name.encode(User.encoding, errors='ignore'), self.card,
                    int(self.group_id) if self.group_id else 0, 0, int(self.user_id))

    def repack73(self):  # with 02 for zk8 (size73)
        # password 6s + 0x00 + 0x77
        # 0,0 => 7sx group id, timezone?
        return pack("<BHB8s24sIB7sx24s", 2, self.uid, self.privilege,
                    self.password.encode(User.encoding, errors='ignore'),
                    self.name.encode(User.encoding, errors='ignore'), self.card, 1,
                    str(self.group_id).encode(User.encoding, errors='ignore'),
                    str(self.user_id).encode(User.encoding, errors='ignore'))

    def __str__(self):
        return '<User>: [uid:{}, name:{} user_id:{}]'.format(self.uid, self.name, self.user_id)

    def __repr__(self):
        return '<User>: [uid:{}, name:{} user_id:{}]'.format(self.uid, self.name, self.user_id)


# END BASE


# START ERROR
class FPError(Exception):
    pass


class FPErrorConnection(FPError):
    pass


class FPErrorResponse(FPError):
    pass


class FPNetworkError(FPError):
    pass


# STOP ERROR

# START USER
class User(object):
    encoding = 'UTF-8'

    def __init__(self, uid, name, privilege, password='', group_id='', user_id='', card=0):
        self.uid = uid
        self.name = str(name)
        self.privilege = privilege
        self.password = str(password)
        self.group_id = str(group_id)
        self.user_id = user_id
        self.card = int(card)  # 64 int to 40 bit int

    @staticmethod
    def json_unpack(json):
        # validate?
        return User(
            uid=json['uid'],
            name=json['name'],
            privilege=json['privilege'],
            password=json['password'],
            group_id=json['group_id'],
            user_id=json['user_id'],
            card=json['card']
        )

    def repack29(self):  # with 02 for zk6 (size 29)
        return pack("<BHB5s8sIxBhI", 2, self.uid, self.privilege, self.password.encode(User.encoding, errors='ignore'),
                    self.name.encode(User.encoding, errors='ignore'), self.card,
                    int(self.group_id) if self.group_id else 0, 0, int(self.user_id))

    def repack73(self):  # with 02 for zk8 (size73)
        # password 6s + 0x00 + 0x77
        # 0,0 => 7sx group id, timezone?
        return pack("<BHB8s24sIB7sx24s", 2, self.uid, self.privilege,
                    self.password.encode(User.encoding, errors='ignore'),
                    self.name.encode(User.encoding, errors='ignore'), self.card, 1,
                    str(self.group_id).encode(User.encoding, errors='ignore'),
                    str(self.user_id).encode(User.encoding, errors='ignore'))

    def __str__(self):
        return '<User>: [uid:{}, name:{} user_id:{}]'.format(self.uid, self.name, self.user_id)

    def __repr__(self):
        return '<User>: [uid:{}, name:{} user_id:{}]'.format(self.uid, self.name, self.user_id)


# END USER

class pyfp:
    def __init__(self):
        print('''
       }--------------{+} niko366 {+}--------------{
       }--------{+}  GitHub.com/niko366/fingerprint_solution {+}--------{
    ''' + '''
       {1}--Informasi Mesin
       {2}--Users
       {3}--Absensi
       {4}--Pengaturan
       {5}--More
       {99}-EXIT\n
     ''')
        choice = input(pyfpPrompt)
        clearScr()
        if choice == "1":
            print("nomor 1")
            information()


class information:
    menuLogo = '''
    88 88b 88 888888  dP"Yb
    88 88Yb88 88__   dP   Yb
    88 88 Y88 88""   Yb   dP
    88 88  Y8 88      YbodP
    '''

    def __init__(self):
        clearScr()
        print(self.menuLogo)

        try:
            conn = None
            ip = input(ip_fp)
            port = int(input(port_fp))
            print("")
            # ip = "10.100.250.10"
            zk = FP(ip, port, timeout=5, password=0, force_udp=False, ommit_ping=False)
            print('Menghubungkan ke mesin ...')
            conn = zk.connect()
            net = conn.get_network_params()
            print('SDK build=1      : %s' % conn.set_sdk_build_1())  # why?
            print('Disabling device ... \n')
            conn.disable_device()
            conn.read_sizes()
            print(conn)
            print(f'Nama mesin\t\t: {conn.get_device_name()}')
            print(f'Serial Number\t\t: {conn.get_serialnumber()}')
            print(f'Firmware Version\t: {conn.get_firmware_version()}')
            print(f'Platform\t\t: {conn.get_platform()}')
            print(f'Pin Width\t\t: {conn.get_pin_width()}')
            print('IP address\t\t: {} '.format(net['ip']))
            print('mask\t\t\t: {} '.format(net['mask']))
            print('gateway\t\t\t: {}'.format(net['gateway']))
            print(f'MAC\t\t\t: {conn.get_mac()}')
            print(".............")
            fmt = conn.get_extend_fmt()
            print('ExtendFmt\t\t: {}'.format(fmt))
            fmt = conn.get_user_extend_fmt()
            print('UsrExtFmt\t\t: {}'.format(fmt))
            print('Face FunOn\t\t: {}'.format(conn.get_face_fun_on()))
            print('Face Version\t\t: {}'.format(conn.get_face_version()))
            print('Finger Version\t\t: {}'.format(conn.get_fp_version()))
            print('Old Firm compat\t\t: {}'.format(conn.get_compat_old_firmware()))
            print('\n')
            print('')

        except Exception as e:
            print("Process terminate : {}".format(e))
            print("Error: %s" % sys.exc_info()[0])
            print('-' * 60)
            traceback.print_exc(file=sys.stdout)
            print('-' * 60)
        finally:
            if conn:
                print('Enabling device ...')
                conn.enable_device()
                conn.disconnect()
                print('ok bye!')
                print('')


if __name__ == "__main__":
    try:
        pyfp()
    except KeyboardInterrupt:
        print(" Terima kasih...\n")
        time.sleep(0.25)
