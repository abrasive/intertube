import socket
import nacl.secret

class SecretPipe(object):
    @classmethod
    def make_key(klass):
        return nacl.utils.random(nacl.secret.SecretBox.KEY_SIZE)

    def __init__(self, lport, rhost, rport, key):
        self.box = nacl.secret.SecretBox(key)

        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("0.0.0.0", lport))
        self.sock.connect((rhost, rport))

    def send(self, data):
        crypted = self.box.encrypt(data)
        self.sock.send(crypted)

    def recv(self):
        try:
            return self.box.decrypt(self.sock.recv(8192))
        except (nacl.exceptions.ValueError, nacl.exceptions.CryptoError):
            print "Bad packet received (wrong key?)"
            return

    def fileno(self):
        return self.sock.fileno()
