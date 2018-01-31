import socket
import nacl.secret
import dns.resolver
import re
import time

class SecretPipe(object):
    @classmethod
    def make_key(klass):
        return nacl.utils.random(nacl.secret.SecretBox.KEY_SIZE)

    def __init__(self, lport, rhost, rport, key):
        self.box = nacl.secret.SecretBox(key)

        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("0.0.0.0", lport))
        self.rhost = rhost
        self.rport = rport
        self.peer = (rhost, rport)
        self.last_dns = 0
        self.use_dns = not re.match('^(\d+\.){3}\d+$', rhost)
        self.last_rx = 0
        self.reconnect()

    def send(self, data):
        crypted = self.box.encrypt(data)
        try:
            self.sock.send(crypted)
        except socket.error:
            self.reconnect()

        if time.time() > self.last_rx + 30:
            self.last_rx = time.time()
            self.reconnect()

    def recv(self):
        self.last_rx = time.time()
        try:
            return self.box.decrypt(self.sock.recv(8192))
        except (nacl.exceptions.ValueError, nacl.exceptions.CryptoError):
            print "Bad packet received (wrong key?)"
            return
        except socket.error:
            self.reconnect()

    def fileno(self):
        return self.sock.fileno()

    def query_dns(self):
        self.last_dns = time.time()
        try:
            ipaddr = dns.resolver.query(self.rhost, 'A')[0].address
        except Exception, e:
            print e
            return

        if ipaddr != self.peer[0]:
            print "New peer address found: %s" % ipaddr
            self.peer = (ipaddr, self.rport)

    def reconnect(self):
        if self.use_dns and time.time() > (self.last_dns + 60):
            self.query_dns()

        self.sock.connect(self.peer)
