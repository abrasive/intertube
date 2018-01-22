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

if __name__ == "__main__":
    import select
    key = SecretPipe.make_key()
    print repr(key)
    key = "scoo"*8

    import sys
    localport = int(sys.argv[1])
    remotehost = sys.argv[2]
    remoteport = int(sys.argv[3])

    pipe = SecretPipe(localport, remotehost, remoteport, key)

    while True:
        r, w, x = select.select([pipe.sock], [], [], 10)

        if pipe.sock in r:
            print repr(pipe.recv())
        else:
            pipe.send("")
