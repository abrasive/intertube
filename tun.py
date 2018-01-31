import os
import ctypes
import fcntl
import socket
import atexit
import sys

class ifreq_payload(ctypes.Union):
    _fields_ = [
        ('ifr_flags', ctypes.c_ushort),
        ('ifr_mtu', ctypes.c_int),
    ]

class ifreq(ctypes.Structure):
    _fields_ = [
        ('ifr_name', ctypes.c_char * 16),
        ('payload', ifreq_payload),
    ]

class TAP(object):
    def set_mtu_up(self, ifr, mtu):
        ifr.payload.ifr_mtu = mtu
        ctl_af = getattr(socket, self.CTL_AF)
        s = socket.socket(ctl_af, socket.SOCK_RAW)
        fcntl.ioctl(s, self.SIOCSIFMTU, ifr)
        fcntl.ioctl(s, self.SIOCGIFFLAGS, ifr)
        ifr.payload.ifr_flags |= self.IFF_UP
        fcntl.ioctl(s, self.SIOCSIFFLAGS, ifr)
        s.close()

    def fileno(self):
        return self.fd

    def write(self, data):
        os.write(self.fd, data)

    def read(self):
        return os.read(self.fd, 8192)

class LinuxTAP(TAP):
    TUNSETIFF = 0x400454CA
    IFF_TAP = 0x0002
    IFF_NO_PI = 0x1000
    SIOCSIFMTU = 0x8922
    SIOCSIFFLAGS = 0x8914
    SIOCGIFFLAGS = 0x8913
    IFF_UP = 1
    CTL_AF = 'AF_PACKET'

    def __init__(self, mtu):
        self.fd = os.open('/dev/net/tun', os.O_RDWR)

        ifr = ifreq()
        ifr.payload.ifr_flags = self.IFF_TAP | self.IFF_NO_PI
        fcntl.ioctl(self.fd, self.TUNSETIFF, ifr)
        self.iface = ifr.ifr_name

        self.set_mtu_up(ifr, mtu)

    def close(self):
        os.close(self.fd)

class BSDTAP(TAP):
    TAPGIFNAME = 0x4020745d
    SIOCIFDESTROY = 0x80206979
    SIOCSIFFLAGS = 0x80206910
    SIOCGIFFLAGS = 0xc0206911
    SIOCSIFMTU = 0x80206934
    IFF_UP = 1
    CTL_AF = 'AF_INET'

    def __init__(self, mtu):
        self.fd = os.open('/dev/tap', os.O_RDWR)

        ifr = ifreq()
        fcntl.ioctl(self.fd, self.TAPGIFNAME, ifr)
        self.iface = ifr.ifr_name

        # BSD TAP interfaces have to be explicitly destroyed
        atexit.register(self.close)

        self.set_mtu_up(ifr, mtu)

    def close(self):
        os.close(self.fd)
        ifr = ifreq()
        ifr.ifr_name = self.iface
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW)
        fcntl.ioctl(s, self.SIOCIFDESTROY, ifr)
        s.close()

def mktap(mtu):
    if sys.platform.startswith('linux'):
        return LinuxTAP(mtu)
    else:
        return BSDTAP(mtu)
