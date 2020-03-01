#!/bin/env python
# -*- coding: utf8 -*-

import random
import tempfile
import time


try:
    import socketserver
except ImportError:
    import SocketServer
    socketserver = SocketServer

import sys
sys.path.append('.')

from pyicap import *

class ThreadingSimpleServer(socketserver.ThreadingMixIn, ICAPServer):
    pass

class ICAPHandler(BaseICAPRequestHandler):

    def service_OPTIONS(self):
        self.set_icap_response(200)
        self.set_icap_header(b'Methods', b'RESPMOD')
        self.set_icap_header(b'Service', b'PyICAP Server 1.0')
        self.set_icap_header(b'Preview', b'0')
        self.set_icap_header(b'Transfer-Preview', b'*')
        self.set_icap_header(b'Transfer-Ignore', b'jpg,jpeg,gif,png,swf,flv')
        self.set_icap_header(b'Transfer-Complete', b'')
        self.set_icap_header(b'Max-Connections', b'100')
        self.set_icap_header(b'Options-TTL', b'3600')
        self.send_headers(False)

    def read_into(self, f):
        while True:
            try:
                chunk = self.read_chunk()
                if chunk == b'':
                    return
                f.write(chunk)
            except:
                return;
    def service_RESPMOD(self):
        self.set_icap_response(200)

        self.set_enc_status(b' '.join(self.enc_res_status))
        for h in self.enc_res_headers:
            for v in self.enc_res_headers[h]:
                self.set_enc_header(h, v)

        if not self.has_body:
            self.send_headers(False)
            return
        
        # Read everything from the response to a temporary file
        # This file can be placed onto a tmpfs filesystem for more performance
        with tempfile.NamedTemporaryFile(prefix='pyicap.', suffix='.tmp') as upstream:
            self.read_into(upstream)
            if self.preview and not self.ieof:
                self.cont()
                self.read_into(upstream)
            upstream.seek(0)
            
            # And write it to downstream
            content = upstream.read()
            print(content)
            self.write_chunk(content)
            
 def handle_one_request(self):
        """Handle a single HTTP request.
        You normally don't need to override this method; see the class
        __doc__ string for information on how to handle specific HTTP
        commands such as GET and POST.
        """

        # Initialize handler state
        self.enc_req = None
        self.enc_req_headers = {}
        self.enc_res_status = None
        self.enc_res_headers = {}
        self.has_body = False
        self.servicename = None
        self.encapsulated = {}
        self.ieof = False
        self.eob = False
        self.methos = None
        self.preview = None
        self.allow = set()
        self.client_ip = None

        self.icap_headers = {}
        self.enc_headers = {}
        self.enc_status = None  # Seriously, need better names
        self.enc_request = None

        self.icap_response_code = None

        try:
            self.raw_requestline = self.rfile.readline(65537)

            if not self.raw_requestline:
                self.close_connection = True
                return

            self.parse_request()

            mname = (self.servicename + b'_' + self.command).decode("utf-8")
            if not hasattr(self, mname):
                self.log_error("%s not found" % mname)
                raise ICAPError(404)

            method = getattr(self, mname)
            if not isinstance(method, collections.Callable):
                raise ICAPError(404)
            method()
            self.wfile.flush()
            self.log_request(self.icap_response_code)
        except socket.timeout as e:
            self.log_error("Request timed out: %r", e)
            self.close_connection = 1
        except ConnectionResetError as e:
            return
        except ICAPError as e:
            msg = e.message[0] if isinstance(e.message, tuple) else e.message
            self.send_error(e.code, msg)
        #except:
        #    self.send_error(500)
port = 13440

server = ThreadingSimpleServer((b'', port), ICAPHandler)
try:
    while 1:
        try: 
            server.handle_request()
        except:
            time.sleep(1)

except KeyboardInterrupt:
    print("Finished")
