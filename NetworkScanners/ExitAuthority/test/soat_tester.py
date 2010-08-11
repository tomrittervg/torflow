import socket
import SocketServer
import time
from BaseHTTPServer import HTTPServer, BaseHTTPRequestHandler
from OpenSSL import SSL, crypto


DIRECT_RESP = """\
<html>
<head> <title>Direct Response</title> </head>
<body>
<center> It works! </center>
</body>
</html>
"""

TOR_RESP= """\
<html>
<head> <title>Tor Response</title> </head>
<body>
<center> Tamper tamper tamper</center>
</body>
</html>
"""

class SSLServer(HTTPServer):
  def server_bind(self):
    HTTPServer.server_bind(self)
    pkey = crypto.PKey()
    pkey.generate_key(crypto.TYPE_RSA, 1024)
    x509 = crypto.X509()
    x509.set_pubkey(pkey)
    x509.get_subject().commonName = self.server_name
    now = time.strftime("%Y%m%d%H%M%S")
    x509.set_notBefore(now + "-1200")
    x509.set_notAfter(now + "+1200")
    ctx = SSL.Context(SSL.SSLv23_METHOD)
    ctx.use_privatekey(pkey)
    ctx.use_certificate(x509)
    self.socket = SSL.Connection(ctx, self.socket)

class Tester:
  direct_ip = "127.0.0.1"
  exit_ip = None # By default 

class HTTPTester(BaseHTTPRequestHandler, Tester):
  server=HTTPServer
  port=80
  def do_GET(self):
    if self.client_address[0] == self.direct_ip:
      self.direct_GET()
    elif self.exit_ip is None:
      # If no exit_ip is specified, then assume everyone except direct_ip is a Tor Exit (what a world that'd be!)
      self.tor_GET()
    else: # Only serve the Tor result to exit_ip
      if self.client_address[0] == self.exit_ip:
        self.tor_GET()
      else: # Everyone else gets 404'd
        self.send_error(401)

  def direct_GET(self):
    self.send_response(200)
    self.send_header("Content-type", "text/html")
    self.send_header("Content-Length", str(len(DIRECT_RESP)))
    self.end_headers()
    self.wfile.write(DIRECT_RESP)

  def tor_GET(self):
    self.send_response(200)
    self.send_header("Content-type", "text/html")
    self.send_header("Content-Length", str(len(TOR_RESP)))
    self.end_headers()
    self.wfile.write(TOR_RESP)


class HTTPSTester(HTTPTester):
  server=SSLServer
  port=443
  def setup(self):
    self.connection = self.request
    self.rfile = socket._fileobject(self.connection, "rb", self.rbufsize)
    self.wfile = socket._fileobject(self.connection, "wb", self.wbufsize)

def usage(argv):
  print "Usage: %s --exit=<exit ip> [options]" % argv[0]

if __name__ == '__main__':
  import sys
  import getopt
  try:
    flags,rest = getopt.getopt(sys.argv[1:], "", ["exit=", "direct=", "test="])
  except getopt.GetoptError,err:
    print err
    usage(sys.argv)

  test = "HTTP"
  for flag, val in flags:
    if flag == "--exit":
      Tester.exit_ip = val
    elif flag == "--direct":
      Tester.direct_ip = val
    elif flag == "--test":
      test = val

  tester = globals().get(test+"Tester")
  if not tester:
    print "No such test, " + test
    sys.exit(1)
  print "Serving %s on %d" % (test, tester.port)
  try:
    tester.server(('', tester.port), tester).serve_forever()
  except KeyboardInterrupt:
    print "Done"
