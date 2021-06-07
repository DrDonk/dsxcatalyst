# Copyright (c) 2015 Radoslav Gerganov
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the 'License') you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an 'AS IS' BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

from __future__ import print_function
# import urlparse
# import websockify
import socket
import ssl
import base64
import hashlib
import os
# import random

# VMAD_OK = 200
# VMAD_WELCOME = 220
# VMAD_LOGINOK = 230
# VMAD_NEEDPASSWD = 331
# VMAD_USER_CMD = 'USER'
# VMAD_PASS_CMD = 'PASS'
# VMAD_THUMB_CMD = 'THUMBPRINT'
# VMAD_CONNECT_CMD = 'CONNECT'

VMAUTHD_VERSION_MAJOR = 1
VMAUTHD_VERSION_MINOR = 10
VMAUTHD_COMPATIBLE_VERSION_MAJOR = 1
VMAUTHD_COMPATIBLE_VERSION_MINOR = 0
VMAD_T_SUCCESS = 200
VMAD_T_INPUTREQ = 300
VMAD_T_ERROR = 400
VMAD_T_FAIL = 500
VMAD_T_TICKET = 600
VMAD_F_SYNTAX = 0
VMAD_F_INF = 10
VMAD_F_CONNECT = 20
VMAD_F_AUTH = 30
VMAD_F_PERM = 50
VMAD_WELCOME = 220
VMAD_GOODBYE = 221
VMAD_OK = 200
VMAD_BADCOMMAND = 500
VMAD_BADARGS = 501
VMAD_MALFORMED = 502
VMAD_LOGINOK = 230
VMAD_NOTLOGGEDIN = 530
VMAD_NEEDPASSWD = 331
VMAD_USERFIRST = 503
VMAD_CONFIGPROBLEM = 510
VMAD_VMSTARTPROBLEM = 511
VMAD_VMSERVERDPROBLEM = 512
VMAD_TICKETERROR = 513
VMAD_CONNECTPROBLEM = 514
VMAD_NOACCESS = 550
VMAD_NOTREGISTERED = 551
VMAD_VMBUSY = 552
VMAD_NOSUCHVM = 553
VMAD_NOSUCHSERVICE = 554
VMAD_TICKET = 630
AUTHD_CNX_SECRET = 'InSeCuRe'
VMAUTHD_BANNER_COMMAND = 'BANNER'
VMAUTHD_THUMBPRINT_COMMAND = 'THUMBPRINT'
VMAUTHD_GLOBAL_COMMAND = 'GLOBAL'
VMAUTHD_CONNECT_COMMAND = 'CONNECT'
VMAUTHD_CONNECT_ARGV_COMMAND = 'CONNECT_ARGV'
VMAUTHD_CONNECT_DEBUG_ARGV_COMMAND = 'CONNECT_DEBUG_ARGV'
VMAUTHD_CONNECT_STATS_ARGV_COMMAND = 'CONNECT_STATS_ARGV'
VMAUTHD_CONNECT_NOSTART_COMMAND = 'CONNECT_NOSTART'
VMAUTHD_CONNECT_VPXA_COMMAND = 'CONNECT_VPXA'
VMAUTHD_START_COMMAND = 'START'
VMAUTHD_START_DEBUG_COMMAND = 'STARTDEBUG'
VMAUTHD_TOKENKEY_COMMAND = 'TOKENKEY'
VMAUTHD_USER_COMMAND = 'USER'
VMAUTHD_PLAINTEXT_PASSWD_COMMAND = 'PASS'
VMAUTHD_MUNGED_PASSWD_COMMAND = 'XPAS'
VMAUTHD_PROXY_COMMAND = 'PROXY'
VMAUTHD_SESSION_COMMAND = 'SESSION'
VMAUTHD_QUIT_COMMAND = 'QUIT'
VMAUTHD_CONNECT_MSG = '200 Connect'
VMAUTHD_HELLO_MSG = '220 VMware Authentication Daemon Version'
VMAUTHD_STARTED_MSG = '200 Start'
VMAUTHD_TICKET_MSG = '630 Ticket'
VMAUTHD_VMXARGS_SUPPORTED = 'VMXARGS supported'
VMAUTHD_ESCAPE_CHARACTER = '%'


def expect(sock, code):
    line = sock.recv(1024)
    recv_code, msg = line.split()[0:2]
    print(line)
    if code != int(recv_code):
        raise Exception('Expected %d but received %d' % (code, int(recv_code)))
    return msg


def handshake(host, port, cfg_file):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((host, port))
        expect(sock, VMAD_WELCOME)
        sock = ssl.wrap_socket(sock)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        cert = sock.getpeercert(binary_form=True)
        h = hashlib.sha1()
        h.update(cert)
        thumbprint = h.hexdigest()
        if thumbprint != h.hexdigest():
            raise Exception('Server thumbprint doesn\'t match')
        sock.write('%s %s\r\n' % (VMAUTHD_USER_COMMAND, 'root'))
        expect(sock, VMAD_NEEDPASSWD)
        sock.write('%s %s\r\n' % (VMAUTHD_PLAINTEXT_PASSWD_COMMAND, 'password'))
        expect(sock, VMAD_LOGINOK)
        sock.write('%s\r\n' % VMAUTHD_TOKENKEY_COMMAND)
        expect(sock, VMAD_OK)
        rand = os.urandom(12)
        rand = base64.b64encode(rand)
        sock.write('%s %s\r\n' % (VMAUTHD_THUMBPRINT_COMMAND, rand))
        thumbprint2 = expect(sock, VMAD_OK)
        thumbprint2 = thumbprint2.replace(':', '').lower()
        sock.write('%s %s mks\r\n' % (VMAUTHD_CONNECT_COMMAND, cfg_file))
        expect(sock, VMAD_OK)
        sock2 = ssl.wrap_socket(sock)
        cert2 = sock2.getpeercert(binary_form=True)
        h = hashlib.sha1()
        h.update(cert2)
        if thumbprint2 != h.hexdigest():
            raise Exception('Second thumbprint doesn\'t match')
        sock2.write(rand)
        return sock2
    except:
        print('Port 902 is not accessible!')
        # sock.write('%s\r\n' % VMAUTHD_QUIT_COMMAND)
        # expect(sock, VMAD_OK)


def main():
    handshake('192.168.8.65', 902, '/vmfs/volumes/5501e2b0-e9ec34b6-81ff-000c2987bb8f/vm-tcl/vm-tcl.vmx')
    # handshake('localhost', 902, '/Users/i049299/vmimages/esxi650/esxi6.vmx')

if __name__ == '__main__':
    main()