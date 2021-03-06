#!/bin/env python
# -*- coding: utf8 -*-

import random
import tempfile
import time
import socket
import collections
import gzip
import imghdr

try:
    from urllib.parse import urlparse
except ImportError:
    from urlparse import urlparse

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
    def read_into(self, f):
        while True:
            try:
                chunk = self.read_chunk()
                if chunk == b'':
                    return
                f.write(chunk)
            except:
                return

    def parse_request(self):
        """Parse a request (internal).
        The request should be stored in self.raw_requestline; the results
        are in self.command, self.request_uri, self.request_version and
        self.headers.
        Return True for success, False for failure; on failure, an
        error is sent back.
        """
        self.command = None
        self.request_version = version = 'ICAP/1.0'

        # Default behavior is to leave connection open
        self.close_connection = False

        requestline = self.raw_requestline.rstrip(b'\r\n')
        self.requestline = requestline
        self.log_error(self.requestline)
        words = requestline.split()
        if len(words) != 3:
            raise ICAPError(400, "Bad request syntax (%r)" % requestline)

        command, request_uri, version = words

        if version[:5] != b'ICAP/':
            raise ICAPError(400, "Bad request protocol, only accepting ICAP")

        if command not in (b'OPTIONS', b'REQMOD', b'RESPMOD'):
            raise ICAPError(501, "command %r is not implemented" % command)

        try:
            base_version_number = version.split(b'/', 1)[1]
            version_number = base_version_number.split(b".")
            # RFC 2145 section 3.1 says there can be only one "." and
            #   - major and minor numbers MUST be treated as
            #      separate integers;
            #   - ICAP/2.4 is a lower version than ICAP/2.13, which in
            #      turn is lower than ICAP/12.3;
            #   - Leading zeros MUST be ignored by recipients.
            if len(version_number) != 2:
                raise ValueError
            version_number = int(version_number[0]), int(version_number[1])
        except (ValueError, IndexError):
            raise ICAPError(400, "Bad request version (%r)" % version)

        if version_number != (1, 0):
            raise ICAPError(
                505, "Invalid ICAP Version (%s)" % base_version_number
            )

        self.command, self.request_uri, self.request_version = \
            command, request_uri, version

        # Examine the headers and look for a Connection directive
        self.headers = self._read_headers()

        conntype = self.headers.get(b'connection', [b''])[0]
        if conntype.lower() == b'close':
            self.close_connection = True

        self.encapsulated = {}
        if self.command in [b'RESPMOD', b'REQMOD']:
            for enc in self.headers.get(b'encapsulated', [b''])[0].split(b','):
                # TODO: raise ICAPError if Encapsulated is malformed or empty
                if len(enc.strip().split(b'=')) > 1:
                    k, v = enc.strip().split(b'=')
                    self.encapsulated[k] = int(v)

        self.preview = self.headers.get(b'preview', [None])[0]
        self.allow = [
            x.strip() for x in self.headers.get(b'allow', [b''])[0].split(b',')
        ]
        self.client_ip = self.headers.get(
            b'x-client-ip', b'No X-Client-IP header')[0]

        if self.command == b'REQMOD':
            if b'req-hdr' in self.encapsulated:
                self.enc_req = self._read_request()
                self.enc_req_headers = self._read_headers()
            if b'req-body' in self.encapsulated:
                self.has_body = True
        elif self.command == b'RESPMOD':
            if b'req-hdr' in self.encapsulated:
                self.enc_req = self._read_request()
                self.enc_req_headers = self._read_headers()
            if b'res-hdr' in self.encapsulated:
                self.enc_res_status = self._read_status()
                self.enc_res_headers = self._read_headers()
            if b'res-body' in self.encapsulated:
                self.has_body = True
        # Else: OPTIONS. No encapsulation.

        # Parse service name
        # TODO: document "url routing"
        self.servicename = urlparse(self.request_uri)[2].strip(b'/')
            
    def handle_one_request(self):
        def call_method():
            mname = (self.servicename + b'_' + self.command).decode("utf-8")
            if not hasattr(self, mname):
                self.log_error("%s not found" % mname)
                raise ICAPError(404)

            method = getattr(self, mname)
            if not isinstance(method, collections.Callable):
                raise ICAPError(404)
            method()
            self.close_connection = True
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
            self.log_error(self.raw_requestline)
            if not self.raw_requestline:
                self.close_connection = True
                return
            self.parse_request()
            call_method()
            self.wfile.flush()
            self.log_request(self.icap_response_code)
        except socket.timeout as e:
            self.log_error("Request timed out: %r", e)
            self.close_connection = 1
        except ConnectionResetError as e:
            self.log_error("Connection reset error: %r", e)
            self.close_connection = 1
        except ICAPError as e:
            msg = e.message[0] if isinstance(e.message, tuple) else e.message
            self.send_error(e.code, msg)
        #except:
        #    self.send_error(500)

    def servicereq_OPTIONS(self):
        self.set_icap_response(200)
        self.set_icap_header(b'Methods', b'REQMOD')
        self.set_icap_header(b'Service', b'PyICAP Server 1.0')
        try:
            del self.enc_req_headers[b'x-forwarded-for']
        except:
             pass
        try:    
            del self.enc_res_headers[b'x-forwarded-for']
        except:
            pass
        try:    
            del self.enc_res_headers[b'via']
        except:
            pass
        try:
            del self.enc_req_headers[b'via']
        except:
             pass
        self.send_headers(False)

    def servicereq_REQMOD(self):
        self.set_icap_response(200)
        print(self.enc_req_headers)
        print(self.enc_res_headers)
        try:
            del self.enc_req_headers[b'x-forwarded-for']
        except:
             pass
        try:    
            del self.enc_res_headers[b'x-forwarded-for']
        except:
            pass

        try:    
            del self.enc_res_headers[b'via']
        except:
            pass
        try:
            del self.enc_req_headers[b'via']
        except:
             pass

        self.set_enc_request(b' '.join(self.enc_req))
        for h in self.enc_req_headers:
            for v in self.enc_req_headers[h]:
                self.set_enc_header(h, v)

        # Copy the request body (in case of a POST for example)
        if not self.has_body:
            self.send_headers(False)
            return
        else:
           with tempfile.NamedTemporaryFile(prefix='pyicap2.', suffix='.tmp') as upstream:
               self.read_into(upstream)
               if self.preview and not self.ieof:
                   self.cont()
                   self.read_into(upstream)
               else:
                   self.send_headers(True)
                   upstream.seek(0)
                   content = upstream.read()
                   if len(content) > 0:
                      self.write_chunk(content)
                      self.write_chunk(b'')
                      return
               upstream.seek(0)
               try:
                   with gzip.open(upstream, "rb") as f:
                       data = f.read()
               except:
                   data = upstream.read()
                   pass
               print (data)
           # And write it to downstream
               upstream.seek(0)
               content = upstream.read()
               self.send_headers(True)
               self.write_chunk(content)


port = 13441

server = ThreadingSimpleServer((b'', port), ICAPHandler)
try:
    while 1:
        server.handle_request()
except KeyboardInterrupt:
    print("Finished")
