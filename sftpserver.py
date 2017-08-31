#!/usr/bin/python

import os
import time
import socket
import argparse
import sys
import textwrap
import paramiko
import logging

HOST, PORT = '0.0.0.0', 3373
RSA_LENGTH = 4096
BACKLOG = 10
log = logging.getLogger('sftpserver')
# logging.basicConfig(level=logging.INFO,
                  # format='%(asctime)s %(levelname)s: %(message)s',
                  # datefmt='%Y-%m-%d %H:%M:%S')
LOGGING_LEVELS = {'critical': logging.CRITICAL,
                  'error': logging.ERROR,
                  'warning': logging.WARNING,
                  'info': logging.INFO,
                  'debug': logging.DEBUG}

class StubServer (paramiko.ServerInterface):
    def __init__(self, users):
        self.users=users
        super(paramiko.ServerInterface, self).__init__()
        
    def check_auth_password(self, username, password):
        # all are disallowed
        return paramiko.AUTH_FAILED
        
    def check_auth_publickey(self, username, key):
        keyb64=key.get_base64()
        log.debug("check_auth_publickey(%s,%s)" % (username,keyb64))
        if self.users.has_key(username) and self.users[username]==keyb64:
            log.info("User %s authenticated by publicKey" % username )
            return paramiko.AUTH_SUCCESSFUL
        return paramiko.AUTH_FAILED
        
    def check_channel_request(self, kind, chanid):
        return paramiko.OPEN_SUCCEEDED

    def get_allowed_auths(self, username):
        """List availble auth mechanisms."""
        return "publickey"
        

class StubSFTPHandle (paramiko.SFTPHandle):
    def stat(self):
        try:
            return paramiko.SFTPAttributes.from_stat(os.fstat(self.readfile.fileno()))
        except OSError as e:
            return paramiko.SFTPServer.convert_errno(e.errno)

    def chattr(self, attr):
        # python doesn't have equivalents to fchown or fchmod, so we have to
        # use the stored filename
        try:
            paramiko.SFTPServer.set_file_attr(self.filename, attr)
            return paramiko.SFTP_OK
        except OSError as e:
            return paramiko.SFTPServer.convert_errno(e.errno)


class StubSFTPServer (paramiko.SFTPServerInterface):
    # assume current folder is a fine root
    # (the tests always create and eventualy delete a subfolder, so there shouldn't be any mess)
    
    ROOT = os.getcwd() # will be overriden by argparse
    
    def _realpath(self, path):
        return self.ROOT + self.canonicalize(path)

    def list_folder(self, path):
        path = self._realpath(path)
        try:
            out = [ ]
            flist = os.listdir(path)
            for fname in flist:
                attr = paramiko.SFTPAttributes.from_stat(os.stat(os.path.join(path, fname)))
                attr.filename = fname
                out.append(attr)
            return out
        except OSError as e:
            return paramiko.SFTPServer.convert_errno(e.errno)

    def stat(self, path):
        path = self._realpath(path)
        try:
            return paramiko.SFTPAttributes.from_stat(os.stat(path))
        except OSError as e:
            return paramiko.SFTPServer.convert_errno(e.errno)

    def lstat(self, path):
        path = self._realpath(path)
        try:
            return paramiko.SFTPAttributes.from_stat(os.lstat(path))
        except OSError as e:
            return paramiko.SFTPServer.convert_errno(e.errno)

    def open(self, path, flags, attr):
        path = self._realpath(path)
        try:
            binary_flag = getattr(os, 'O_BINARY',  0)
            flags |= binary_flag
            mode = getattr(attr, 'st_mode', None)
            if mode is not None:
                fd = os.open(path, flags, mode)
            else:
                # os.open() defaults to 0777 which is
                # an odd default mode for files
                fd = os.open(path, flags, 0o666)
        except OSError as e:
            return paramiko.SFTPServer.convert_errno(e.errno)
        if (flags & os.O_CREAT) and (attr is not None):
            attr._flags &= ~attr.FLAG_PERMISSIONS
            paramiko.SFTPServer.set_file_attr(path, attr)
        if flags & os.O_WRONLY:
            if flags & os.O_APPEND:
                fstr = 'ab'
            else:
                fstr = 'wb'
        elif flags & os.O_RDWR:
            if flags & os.O_APPEND:
                fstr = 'a+b'
            else:
                fstr = 'r+b'
        else:
            # O_RDONLY (== 0)
            fstr = 'rb'
        try:
            f = os.fdopen(fd, fstr)
        except OSError as e:
            return paramiko.SFTPServer.convert_errno(e.errno)
        fobj = StubSFTPHandle(flags)
        fobj.filename = path
        fobj.readfile = f
        fobj.writefile = f
        return fobj

    def remove(self, path):
        path = self._realpath(path)
        try:
            os.remove(path)
        except OSError as e:
            return paramiko.SFTPServer.convert_errno(e.errno)
        return paramiko.SFTP_OK

    def rename(self, oldpath, newpath):
        oldpath = self._realpath(oldpath)
        newpath = self._realpath(newpath)
        try:
            os.rename(oldpath, newpath)
        except OSError as e:
            return paramiko.SFTPServer.convert_errno(e.errno)
        return paramiko.SFTP_OK

    def mkdir(self, path, attr):
        path = self._realpath(path)
        try:
            os.mkdir(path)
            if attr is not None:
                paramiko.SFTPServer.set_file_attr(path, attr)
        except OSError as e:
            return paramiko.SFTPServer.convert_errno(e.errno)
        return paramiko.SFTP_OK

    def rmdir(self, path):
        path = self._realpath(path)
        try:
            os.rmdir(path)
        except OSError as e:
            return paramiko.SFTPServer.convert_errno(e.errno)
        return paramiko.SFTP_OK

    def chattr(self, path, attr):
        path = self._realpath(path)
        try:
            paramiko.SFTPServer.set_file_attr(path, attr)
        except OSError as e:
            return paramiko.SFTPServer.convert_errno(e.errno)
        return paramiko.SFTP_OK

    def symlink(self, target_path, path):
        path = self._realpath(path)
        if (len(target_path) > 0) and (target_path[0] == '/'):
            # absolute symlink
            target_path = os.path.join(self.ROOT, target_path[1:])
            if target_path[:2] == '//':
                # bug in os.path.join
                target_path = target_path[1:]
        else:
            # compute relative to path
            abspath = os.path.join(os.path.dirname(path), target_path)
            if abspath[:len(self.ROOT)] != self.ROOT:
                # this symlink isn't going to work anyway -- just break it immediately
                target_path = '<error>'
        try:
            os.symlink(target_path, path)
        except OSError as e:
            return paramiko.SFTPServer.convert_errno(e.errno)
        return paramiko.SFTP_OK

    def readlink(self, path):
        path = self._realpath(path)
        try:
            symlink = os.readlink(path)
        except OSError as e:
            return paramiko.SFTPServer.convert_errno(e.errno)
        # if it's absolute, remove the root
        if os.path.isabs(symlink):
            if symlink[:len(self.ROOT)] == self.ROOT:
                symlink = symlink[len(self.ROOT):]
                if (len(symlink) == 0) or (symlink[0] != '/'):
                    symlink = '/' + symlink
            else:
                symlink = '<error>'
        return symlink

def start_server(host, port, keyfile, level, users):
    paramiko.common.logging.basicConfig(level=level)

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, True)
    server_socket.bind((host, port))
    server_socket.listen(BACKLOG)

    while True:
        conn, addr = server_socket.accept()

        if keyfile!=None:
            host_key = paramiko.RSAKey.from_private_key_file(keyfile)
        else:
            log.info("Generate a new SSH hostkey length=%d" % RSA_LENGTH)
            host_key = paramiko.RSAKey.generate(RSA_LENGTH)
        
        try:
            transport = paramiko.Transport(conn)
            transport.add_server_key(host_key)
            transport.set_subsystem_handler(
                'sftp', paramiko.SFTPServer, StubSFTPServer)

            server = StubServer(users)
            transport.start_server(server=server)

            channel = transport.accept()
            while transport.is_active():
                time.sleep(1)
        except Exception as e:
            log.error(str(e))
                
if __name__ == '__main__':
    
    import json,re

    usage = """\
    usage: sftpserver [options]    
    -U/--user=name:pubkey
    
    ENVIRONMENT VARIABLES:
    USERS  =   username:Base64_encoded_SSH_publickey,...
    PORT=SFTP port to use
    LOGLEVEL=debug|info|warning|error|critical
    ROOT=root_directory
    
    
    Example:

    the private key can be generated using:
    ssh-keygen -t rsa -b 2048 -f sftp.key
    
    python sftpserver.py -k sftp.key --user=pascal.trouvin:"AAAAB3NzaC1yc2EAAAADAQABAAABAQDVlyWD6Ces9sOIF6U4BO9W44sEr7Y9SDZudlIlF6hBKREj7EFqet99cA4hrnz83X/PFgp9Qvv0vnrc1QmCiMNF+siDKGqn5UpbBpCLZpzMs9Iam77w+lFkOLX3P64bfDjBWNVMltcLWZs9c2/VE+AhRKKxxLGPAnVOuUxlldAU7W5+08pSYwUrusY8BLqQ3FOoiWMmw6dCRFCpzkgA+pA0zaHHIbTJQYJAaVd2/xjZkeb9/xvuU4Z4uj/kaYrG2VqsBSwtF+pIBGILIGOiop/wbZ+i3vQxpowMkoHTwnOfy/hGO8JFR16MZf362h0J+DW/AxPPZgPjwjLB/nRofj/P"
    
    sftp -P 3373 -o StrictHostKeyChecking=no -o NoHostAuthenticationForLocalhost=yes pascal.trouvin@127.0.0.1
    """
	
    

    class customAction(argparse._AppendAction):
        def __call__(self,parser,args,values,option_string=None):
            kv=re.compile("[=:]").split(values)
            if len(kv)!=2:
                log.critical("INVALID-USER: "+values)
                parser.print_help()
                sys.exit(-1)
            super(customAction, self).__call__(parser,args,{kv[0]:kv[1]},option_string)

	
    parser = argparse.ArgumentParser(usage=textwrap.dedent(usage))
    parser.add_argument(
        '--host', dest='host', default=HOST,
        help='listen on HOST [default: %(default)s]'
    )
    parser.add_argument(
        '-p', '--port', dest='port', type=int, default=PORT,
        help='listen on PORT [default: %(default)d]'
    )
    parser.add_argument('-l','--level', default='info',
            help='Logging level '+','.join(LOGGING_LEVELS.keys()))
    parser.add_argument(
        '-k', '--keyfile', dest='keyfile', metavar='FILE',
        help='Path to private key, for example /tmp/test_rsa.key,   will be generated automatically is not specified'
    )
    parser.add_argument(
        '-U', '--user', action=customAction,
        help='store users and publicKey:  user:pubkey, can be completed by environment variable USERS'
    )
    parser.add_argument(
        '--root', action='store',
        help='Define the root directory for SFTP server'
    )

    args = parser.parse_args()
    if os.environ.get('LOGLEVEL',False):
        level = LOGGING_LEVELS.get(os.environ['LOGLEVEL'], logging.NOTSET)
    else:
        level = LOGGING_LEVELS.get(args.level, logging.NOTSET)
    logging.basicConfig(level=level,
                      format='%(asctime)s %(levelname)s: %(message)s',
                      datefmt='%Y-%m-%d %H:%M:%S')

    users={}
    if args.user:
        for i in xrange(len(args.user)):
            for u in args.user[i].keys():
                users[u]=args.user[i][u]
    # check if USERS from environment
    patUser=re.compile("([^:=]+)[:=](.*)")
    for user in re.compile("[,; ]").split(os.environ.get('USERS','')):
        if user:
            m = patUser.match(user)
            if not m:
                log.error("USER '"+user+"' is invalid")
                print_help()
                sys.exit(-1)
            (u,k)=m.groups()
            users[u]=k
            
    if users is None:
        parser.print_help()
        sys.exit(-1)
    
    if os.environ.get('ROOT',False):
        StubSFTPServer.ROOT=os.environ['ROOT']
    elif args.root is not None:
        StubSFTPServer.ROOT=args.root
    
    port=args.port
    if os.environ.get('PORT',False):
        port=int(os.environ['PORT'])
        
    log.info("SFTP server root directory set to: %s" % StubSFTPServer.ROOT)
    log.info("SFTP server port: %s:%d" % (args.host,port))
        
    log.debug("USERS: " + json.dumps(users, indent=4, sort_keys=True))

    start_server(args.host, port, args.keyfile, level, users)


