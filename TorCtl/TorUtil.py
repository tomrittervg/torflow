#!/usr/bin/python
# TorCtl.py -- Python module to interface with Tor Control interface.
# Copyright 2007 Mike Perry -- See LICENSE for licensing information.
# Portions Copyright 2005 Nick Matthewson

"""
TorUtil -- Support functions for TorCtl.py and metatroller
"""

import os
import re
import sys
import socket
import binascii
import sha

__all__ = ["Enum", "Enum2", "quote", "escape_dots", "unescape_dots",
      "BufSock", "secret_to_key", "urandom_rng", "s2k_gen", "s2k_check",
      "plog", "ListenSocket"]

class Enum:
  # Helper: define an ordered dense name-to-number 1-1 mapping.
  def __init__(self, start, names):
    self.nameOf = {}
    idx = start
    for name in names:
      setattr(self,name,idx)
      self.nameOf[idx] = name
      idx += 1

class Enum2:
  # Helper: define an ordered sparse name-to-number 1-1 mapping.
  def __init__(self, **args):
    self.__dict__.update(args)
    self.nameOf = {}
    for k,v in args.items():
      self.nameOf[v] = k

def quote(s):
  return re.sub(r'([\r\n\\\"])', r'\\\1', s)

def escape_dots(s, translate_nl=1):
  if translate_nl:
    lines = re.split(r"\r?\n", s)
  else:
    lines = s.split("\r\n")
  if lines and not lines[-1]:
    del lines[-1]
  for i in xrange(len(lines)):
    if lines[i].startswith("."):
      lines[i] = "."+lines[i]
  lines.append(".\r\n")
  return "\r\n".join(lines)

def unescape_dots(s, translate_nl=1):
  lines = s.split("\r\n")

  for i in xrange(len(lines)):
    if lines[i].startswith("."):
      lines[i] = lines[i][1:]

  if lines and lines[-1]:
    lines.append("")

  if translate_nl:
    return "\n".join(lines)
  else:
    return "\r\n".join(lines)

class BufSock:
  def __init__(self, s):
    self._s = s
    self._buf = []

  def readline(self):
    if self._buf:
      idx = self._buf[0].find('\n')
      if idx >= 0:
        result = self._buf[0][:idx+1]
        self._buf[0] = self._buf[0][idx+1:]
        return result

    while 1:
      s = self._s.recv(128)
      if not s: return None
      # XXX: This really does need an exception
      #  raise ConnectionClosed()
      idx = s.find('\n')
      if idx >= 0:
        self._buf.append(s[:idx+1])
        result = "".join(self._buf)
        rest = s[idx+1:]
        if rest:
          self._buf = [ rest ]
        else:
          del self._buf[:]
        return result
      else:
        self._buf.append(s)

  def write(self, s):
    self._s.send(s)

  def close(self):
    self._s.close()

# SocketServer.TCPServer is nuts.. 
class ListenSocket:
  def __init__(self, listen_ip, port):
    msg = None
    self.s = None
    for res in socket.getaddrinfo(listen_ip, port, socket.AF_UNSPEC,
              socket.SOCK_STREAM, 0, socket.AI_PASSIVE):
      af, socktype, proto, canonname, sa = res
      try:
        self.s = socket.socket(af, socktype, proto)
        self.s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
      except socket.error, msg:
        self.s = None
        continue
      try:
        self.s.bind(sa)
        self.s.listen(1)
      except socket.error, msg:
        self.s.close()
        self.s = None
        continue
      break
    if self.s is None:
      raise socket.error(msg)

  def accept(self):
    conn, addr = self.s.accept()
    return conn

  def close(self):
    self.s.close()


def secret_to_key(secret, s2k_specifier):
  """Used to generate a hashed password string. DOCDOC."""
  c = ord(s2k_specifier[8])
  EXPBIAS = 6
  count = (16+(c&15)) << ((c>>4) + EXPBIAS)

  d = sha.new()
  tmp = s2k_specifier[:8]+secret
  slen = len(tmp)
  while count:
    if count > slen:
      d.update(tmp)
      count -= slen
    else:
      d.update(tmp[:count])
      count = 0
  return d.digest()

def urandom_rng(n):
  """Try to read some entropy from the platform entropy source."""
  f = open('/dev/urandom', 'rb')
  try:
    return f.read(n)
  finally:
    f.close()

def s2k_gen(secret, rng=None):
  """DOCDOC"""
  if rng is None:
    if hasattr(os, "urandom"):
      rng = os.urandom
    else:
      rng = urandom_rng
  spec = "%s%s"%(rng(8), chr(96))
  return "16:%s"%(
    binascii.b2a_hex(spec + secret_to_key(secret, spec)))

def s2k_check(secret, k):
  """DOCDOC"""
  assert k[:3] == "16:"

  k =  binascii.a2b_hex(k[3:])
  return secret_to_key(secret, k[:9]) == k[9:]


## XXX: Make this a class?
loglevel = "DEBUG"
loglevels = {"DEBUG" : 0, "INFO" : 1, "NOTICE" : 2, "WARN" : 3, "ERROR" : 4}

def plog(level, msg): # XXX: Timestamps
  if(loglevels[level] >= loglevels[loglevel]):
    print level + ": " + msg
    sys.stdout.flush()

