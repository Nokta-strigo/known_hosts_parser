#!/usr/bin/python3
from base64 import b64decode
import hmac
from struct import unpack
import sys
from os import path


class HashTypeNotSupported(BaseException):
    pass


class PublicKeyParseError(BaseException):
    pass


class PublicKey:
    @staticmethod
    def parse_binary(binary, max_split=None):
        n_split = 0
        parts = []
        while len(binary) > 0 and (max_split is None or n_split < max_split):
            if len(binary) < 4:
                raise PublicKeyParseError
            length = unpack('>I', binary[:4])[0]
            if len(binary) < length + 4:
                raise PublicKeyParseError
            parts.append(binary[4:4 + length])
            binary = binary[4 + length:]
            n_split += 1
        return parts

    def __init__(self, base64_encoded_key):
        self.base64_encoded_key = base64_encoded_key
        binary = b64decode(base64_encoded_key)
        self.parts = self.parse_binary(binary)

    def __repr__(self):
        return str(self.base64_encoded_key)


class KnownHost:
    def __init__(self, line):
        if line.startswith('#') or len(line) == 0:
            return
        self.line = line
        if line.startswith('@'):
            self.markers, line = line.split(' ', 1)
        else:
            self.markers = None
        self.hostname, self.keytype, line = line.split(' ', 2)
        if ' ' in line:
            self.base64_encoded_key, self.comment = line.split(' ', 1)
        else:
            self.base64_encoded_key = line
            self.comment = None
        self.key = PublicKey(self.base64_encoded_key)
        self.hostnames = self.hostname.strip('|').split('|')
        if len(self.hostnames) == 1:
            self.plaintext_host =self.hostnames[0]
        else:
            self.plaintext_host = None
            self.hash_type, self.hostname_salt, self.hostname_hmac = self.hostnames[0], b64decode(self.hostnames[1]), b64decode(self.hostnames[2])
       

    def match(self, host):
        if  self.plaintext_host is not None:
            return self.plaintext_host == host
        if self.hash_type != '1':
            raise HashTypeNotSupported(self.hash_type)
        if hmac.HMAC(self.hostname_salt, host.encode(), 'sha1').digest() == self.hostname_hmac:
            self.plaintext_host = host
            return True
        return False

    def __repr__(self):
        if self.plaintext_host is not None:
            return "%s %s %s" % (self.plaintext_host, self.keytype, self.key)
        else:
            return "%s %s %s" % (self.hostname, self.keytype, self.key)


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("""Search for hostname in ssh known_hosts file. Usage:
{} path_to_known_hosts_file hostname [hostname [hostname]...]""".format(path.split(sys.argv[0])[1]))
        sys.exit()
    known_hosts = []
    with open(sys.argv[1], 'rt') as f:
        for line in f:
            known_hosts.append(KnownHost(line))

    for record in sys.argv[2:]:
        for host in known_hosts:
            if host.match(record):
                print(record)
