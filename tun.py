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

class LinuxTAP(object):
    TUNSETIFF = 0x400454CA
    IFF_TAP = 0x0002
    IFF_NO_PI = 0x1000
    SIOCSIFMTU = 0x8922

    def __init__(self, mtu):
        self.fd = os.open('/dev/net/tun', os.O_RDWR)

        ifr = ifreq()
        ifr.payload.ifr_flags = self.IFF_TAP | self.IFF_NO_PI
        fcntl.ioctl(self.fd, self.TUNSETIFF, ifr)
        self.iface = ifr.ifr_name

        # you can't set the MTU on the tun interface in Linux? herf
        ifr.payload.ifr_mtu = mtu
        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
        fcntl.ioctl(s, self.SIOCSIFMTU, ifr)
        s.close()

    def close(self):
        os.close(self.fd)

    def fileno(self):
        return self.fd

    def write(self, data):
        os.write(self.fd, data)

    def read(self):
        return os.read(self.fd, 8192)

class BSDTAP(object):
    TAPGIFNAME = 0x4020745d
    SIOCIFDESTROY = 0x80206979
    SIOCSIFFLAGS = 0x80206910
    SIOCGIFFLAGS = 0xc0206911
    SIOCSIFMTU = 0x80206934
    IFF_UP = 1

    def __init__(self, mtu):
        self.fd = os.open('/dev/tap', os.O_RDWR)

        ifr = ifreq()
        fcntl.ioctl(self.fd, self.TAPGIFNAME, ifr)
        self.iface = ifr.ifr_name

        # BSD TAP interfaces have to be explicitly destroyed
        atexit.register(self.close)

        s = socket.socket(socket.AF_INET, socket.SOCK_RAW)

        fcntl.ioctl(s, self.SIOCGIFFLAGS, ifr)
        ifr.payload.ifr_flags |= self.IFF_UP
        fcntl.ioctl(s, self.SIOCSIFFLAGS, ifr)

        ifr.payload.ifr_mtu = mtu
        fcntl.ioctl(s, self.SIOCSIFMTU, ifr)

        s.close()

    def close(self):
        os.close(self.fd)
        ifr = ifreq()
        ifr.ifr_name = self.iface
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW)
        fcntl.ioctl(s, self.SIOCIFDESTROY, ifr)
        s.close()

    def fileno(self):
        return self.fd

    def write(self, data):
        os.write(self.fd, data)

    def read(self):
        return os.read(self.fd, 8192)

def mktap(mtu=1280):
    if sys.platform.startswith('linux'):
        return LinuxTAP(mtu)
    else:
        return BSDTAP(mtu)
