#!/usr/bin/python
#
# 2008 Aleksei Gorny, mentored by Mike Perry

'''
Snakes on a Tor exit node scanner

The SoaT scanner checks whether exit nodes behave by initiating connections
to semi-randomly chosen targets using several protocols (http, https, ssh, smtp, imap, etc)
and comparing content received directly and via tor.

It interacts with metatroller and the control port to be aware of the tor network status.

To run SoaT: 
1) make sure you have py-openssl packages installed (see README)
2) open Tor control port in the torrc
3) start metatroller in the background (python ./metatroller.py)
4) start soat (python ./soat.py) with some testing flags (run it without any flags
    to see which options are available)
5) check the results later by running soatstats (python ./soatstats.py)

'''

__all__ = ["ExitNodeScanner", "DNSRebindScanner", "load_wordlist", "get_urls"]

import commands
import getopt
import httplib
import os
import random
import re
from sets import Set
import smtplib
import socket
import string
import sys
import time
import urllib
import urllib2

import soatstats
from soatstats import *

sys.path.append("../")

from TorCtl import TorUtil, TorCtl, PathSupport
from TorCtl.TorUtil import meta_port, meta_host, control_port, control_host, tor_port, tor_host
from TorCtl.TorUtil import *
from TorCtl.PathSupport import *
from TorCtl.TorCtl import Connection, EventHandler

from OpenSSL import *

sys.path.append("./libs/")
from BeautifulSoup.BeautifulSoup import BeautifulSoup, SoupStrainer
from SocksiPy import socks
import Pyssh.pyssh

#
# config stuff
#

# these are used when searching for 'random' urls for testing
wordlist_file = './wordlist.txt'; 
allowed_filetypes = ['all','pdf'] 
result_per_type = 5 

#
# ports to test in the consistency test
#

ports_to_check = [
    ["pop", ExitPolicyRestriction('255.255.255.255', 110), "pops", ExitPolicyRestriction('255.255.255.255', 995)],
    ["imap", ExitPolicyRestriction('255.255.255.255', 143), "imaps", ExitPolicyRestriction('255.255.255.255', 993)],
    ["telnet", ExitPolicyRestriction('255.255.255.255', 23), "ssh", ExitPolicyRestriction('255.255.255.255', 22)],
    ["smtp", ExitPolicyRestriction('255.255.255.255', 25), "smtps", ExitPolicyRestriction('255.255.255.255', 465)],
    ["http", ExitPolicyRestriction('255.255.255.255', 80), "https", ExitPolicyRestriction('255.255.255.255', 443)]
]

#
# non-public IPv4 address ranges network portions
# refer to: www.iana.org/assignments/ipv4-address-space, www.iana.org/assignments/multicast-addresses
# 
ipv4_nonpublic = [
    '00000000',         # default route and its network: 0.0.0.0/8
    '00001010',         # private 10.0.0.0/8
    '01111111',         # loopback 127.0.0.0/8
    '1010100111111110', # link-local 169.254.0.0/16
    '101011000001',     # private 172.16.0.0/12
    '1100000010101000', # private 192.168.0.0/16
    '111'               # multicast & experimental 224.0.0.0/3
]

# tags and attributes to check in the http test: XXX these should be reviewed
# See also: http://ha.ckers.org/xss.html
# Note: the more we add, the greater the potential for false positives...  
# We also only care about the ones that work for FF2/FF3. 
tags_to_check = ['a', 'area', 'base', 'applet', 'embed', 'form', 'frame',
                 'iframe', 'img', 'link', 'object', 'script', 'meta', 'body']
attrs_to_check = ['onclick', 'ondblclick', 'onmousedown', 'onmouseup', 'onmouseover',
                  'onmousemove', 'onmouseout', 'onkeypress','onkeydown','onkeyup']
#
# constants
#

linebreak = '\r\n'

# a simple interface to handle a socket connection
class Client:

    def __init__(self, host, port):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.connect((host, port))
        self.buffer = self.sock.makefile('rb')

    def writeline(self, line):
        self.sock.send(line + linebreak)

    def readline(self):
        response = self.buffer.readline()
        if not response:
            raise EOFError
        elif response[-2:] == linebreak:
            response = response[:-2]
        elif response[-1:] in linebreak:
            response = response[:-1]
        return response 

class DNSRebindScanner(EventHandler):
    ''' 
    A tor control event handler extending TorCtl.EventHandler 
    Monitors for REMAP events (see check_dns_rebind())
    '''
    def __init__(self, exit_node_scanner):
        EventHandler.__init__(self)
        self.__soat = exit_node_scanner

    def stream_status_event(self, event):
        if event.status == 'REMAP':
            octets = map(lambda x: int2bin(x).zfill(8), event.target_host.split('.'))
            ipbin = ''.join(octets)
            for network in ipv4_nonpublic:
                if ipbin[:len(network)] == network:
                    handler = DataHandler()
                    result = DNSRebindTestResult(self.__soat.get_exit_node(), '', TEST_FAILURE)
                    handler.saveResult(result)

class ExitNodeScanner:
    ''' The scanner class '''
    def __init__(self):
        ''' 
        Establish a connection to metatroller & control port, 
        configure metatroller, load the number of previously tested nodes 
        '''
        # establish a metatroller connection
        plog('INFO', 'ExitNodeScanner starting up...')
        try:
            self.__meta = Client(meta_host, meta_port)
        except socket.error:
            plog('ERROR', 'Couldn\'t connect to metatroller. Is it on?')
            exit()
    
        # skip two lines of metatroller introduction
        data = self.__meta.readline()
        data = self.__meta.readline()
        
        # configure metatroller
        commands = [
            'PATHLEN 2',
            'PERCENTFAST 88',
            'USEALLEXITS 1',
            'UNIFORM 0',
            'BWCUTOFF 1',
            'ORDEREXITS 1',
            'GUARDNODES 0',
            'RESETSTATS']
        plog('INFO', 'Executing preliminary configuration commands')
        for c in commands:
            self.__meta.writeline(c)
            reply = self.__meta.readline()
            if reply[:3] != '250': # first three chars indicate the reply code
                reply += self.__meta.readline()
                plog('ERROR', 'Error configuring metatroller (' + command + ' failed)')
                plog('ERROR', reply)
                exit()

        # establish a control port connection
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((control_host, control_port))
            c = Connection(s)
            c.authenticate()
            self.__control = c
        except socket.error, e:
            plog('ERROR', 'Couldn\'t connect to the control port')
            plog('ERROR', e)
            exit()
        except AttributeError, e:
            plog('ERROR', 'A service other that the Tor control port is listening on ' + control_host + ':' + control_port)
            plog('ERROR', e)
            exit()

        # get a data handler
        self.__datahandler = DataHandler()

        # TODO get stats about previous runs
        plog('INFO', 'Loading the previous run stats')

        ssh_results = self.__datahandler.getSsh()
        ssl_results = self.__datahandler.getSsl()
        http_results = self.__datahandler.getHttp()

        # get lists of tested nodes
        self.ssh_tested = Set([x.exit_node for x in ssh_results])
        self.http_tested = Set([x.exit_node for x in http_results])
        self.ssl_tested = Set([x.exit_node for x in ssl_results])
        
        # get the number of failures
        self.ssh_fail = [self.__datahandler.filterResults(ssh_results, protocols=["ssh"], show_bad=True)]
        self.http_fail =  [self.__datahandler.filterResults(http_results, protocols=["http"], show_bad=True)]
        self.ssl_fail = [self.__datahandler.filterResults(ssl_results, protocols=["ssl"], show_bad=True)]

        plog('INFO', 'ExitNodeScanner up and ready')

    def get_exit_node(self):
        ''' ask metatroller for the last exit used '''
        self.__meta.writeline("GETLASTEXIT")
        reply = self.__meta.readline()
        
        if reply[:3] != '250':
            reply += self.__meta.readline()
            plog('ERROR', reply)
            return 0
        
        p = re.compile('250 LASTEXIT=[\S]+')
        m = p.match(reply)
        self.__exit = m.group()[13:] # drop the irrelevant characters    
        plog('NOTICE','Current node: ' + self.__exit)
        return self.__exit

    def get_new_circuit(self):
        ''' tell metatroller to close the current circuit and open a new one '''
        plog('NOTICE', 'Trying to construct a new circuit')
        self.__meta.writeline("NEWEXIT")
        reply = self.__meta.readline()

        if reply[:3] != '250':
            plog('ERROR', 'Choosing a new exit failed')
            plog('ERROR', reply)

    def set_new_exit(self, exit):
        ''' 
        tell metatroller to set the given node as the exit in the next circuit 
        '''
        plog('NOTICE', 'Trying to set ' + `exit` + ' as the exit for the next circuit')
        self.__meta.writeline("SETEXIT $"+exit)
        reply = self.__meta.readline()

        if reply[:3] != '250':
            plog('ERROR', 'Setting ' + exit + ' as the new exit failed')
            plog('ERROR', reply)

    def report_bad_exit(self, exit):
        ''' 
        report an evil exit to the control port using AuthDirBadExit 
        Note: currently not used    
        '''
        # self.__contol.set_option('AuthDirBadExit', exit) ?
        pass

    def get_nodes_for_port(self, port):
        ''' ask control port for a list of nodes that allow exiting to a given port '''
        routers = self.__control.read_routers(self.__control.get_network_status())
        restriction = NodeRestrictionList([FlagsRestriction(["Running", "Valid"]), ExitPolicyRestriction('255.255.255.255', port)])
        return [x for x in routers if restriction.r_is_ok(x)]

    def check_all_exits_port_consistency(self):
        ''' 
        an independent test that finds nodes that allow connections over a common protocol
        while disallowing connections over its secure version (for instance http/https)
        '''

        # get the structure
        routers = self.__control.read_routers(self.__control.get_network_status())
        bad_exits = Set([])
        specific_bad_exits = [None]*len(ports_to_check)
        for i in range(len(ports_to_check)):
            specific_bad_exits[i] = []

        # check exit policies
        for router in routers:
            for i in range(len(ports_to_check)):
                [common_protocol, common_restriction, secure_protocol, secure_restriction] = ports_to_check[i]
                if common_restriction.r_is_ok(router) and not secure_restriction.r_is_ok(router):
                    bad_exits.add(router)
                    specific_bad_exits[i].append(router)
                    plog('INFO', 'Router ' + router.nickname + ' allows ' + common_protocol + ' but not ' + secure_protocol)
    
        # report results
        plog('INFO', 'Total exits: ' + `len(routers)`)
        for i in range(len(ports_to_check)):
            [common_protocol, _, secure_protocol, _] = ports_to_check[i]
            plog('INFO', 'Exits with ' + common_protocol + ' / ' + secure_protocol + ' problem: ' + `len(specific_bad_exits[i])` + ' (~' + `(len(specific_bad_exits[i]) * 100 / len(routers))` + '%)')
        plog('INFO', 'Total bad exits: ' + `len(bad_exits)` + ' (~' + `(len(bad_exits) * 100 / len(routers))` + '%)')

    def check_http(self, address):
        ''' check whether a http connection to a given address is molested '''
        plog('INFO', 'Conducting an http test with destination ' + address)

        defaultsocket = socket.socket
        socks.setdefaultproxy(socks.PROXY_TYPE_SOCKS5, tor_host, tor_port)
        socket.socket = socks.socksocket

        pcontent = self.http_request(address)

        # reset the connection to direct
        socket.socket = defaultsocket

        exit_node = self.get_exit_node()
        if exit_node == 0 or exit_node == '0' or not exit_node:
            plog('INFO', 'We had no exit node to test, skipping to the next test.')
            return TEST_SUCCESS

        # an address representation acceptable for a filename 
        address_file = self.__datahandler.safeFilename(address[7:])

        # if we have no content, we had a connection error
        if pcontent == 0:
            result = HttpTestResult(exit_node, address, 0, TEST_INCONCLUSIVE)
            self.__datahandler.saveResult(result)
            return TEST_INCONCLUSIVE

        elements = SoupStrainer(lambda name, attrs : name in tags_to_check or 
                len(Set(attrs).intersection(Set(attrs_to_check))) > 0)
        pcontent = pcontent.decode('ascii', 'ignore')
        psoup = BeautifulSoup(pcontent, parseOnlyThese=elements)

        # load the original tag structure
        # if we don't have any yet, get it
        soup = 0
        try:
            tag_file = open(http_tags_dir + address_file + '.tags', 'r')
            soup = BeautifulSoup(tag_file.read())
            tag_file.close()
        except IOError:
            content = self.http_request(address)
            content = content.decode('ascii','ignore')
            soup = BeautifulSoup(content, parseOnlyThese=elements)
            tag_file = open(http_tags_dir + address_file + '.tags', 'w')
            tag_file.write(soup.__str__() +  ' ') # the space is needed in case we have some page with no matching tags at all
            tag_file.close()
        except TypeError, e:
            plog('ERROR', 'Failed parsing the tag tree for ' + address)
            plog('ERROR', e)
            return TEST_INCONCLUSIVE
        if soup == 0:
            plog('ERROR', 'Failed to get the correct tag structure for ' + address)
            return TEST_INCONCLUSIVE

        self.http_tested.add(exit_node)

        # compare the content
        # if content matches, everything is ok
        if psoup == soup:
            result = HttpTestResult(exit_node, address, 0, TEST_SUCCESS)
            self.__datahandler.saveResult(result)
            return TEST_SUCCESS

        # if content doesnt match, update the direct content
        content_new = self.http_request(address)
        content_new = content_new.decode('ascii', 'ignore')
        if content_new == 0:
            result = HttpTestResult(exit_node, address, 0, TEST_INCONCLUSIVE)
            self.__datahandler.saveResult(result)
            return TEST_INCONCLUSIVE

        soup_new = BeautifulSoup(content_new, parseOnlyThese=elements)
        # compare the new and old content
        # if they match, means the node has been changing the content
        if soup == soup_new:
            result = HttpTestResult(exit_node, address, 0, TEST_FAILURE)
            self.__datahandler.saveResult(result)
            tag_file = open(http_tags_dir + `exit_node` + '_' + address_file + '.tags', 'w')
            tag_file.write(psoup.__str__())
            tag_file.close()
            return TEST_FAILURE

        # if content has changed outside of tor, update the saved file
        tag_file = open(http_tags_dir + address_file + '.tags', 'w')
        tag_file.write(soup_new.__str__())
        tag_file.close()

        # compare the node content and the new content
        # if it matches, everything is ok
        if psoup == soup_new:
            result = HttpTestResult(exit_node, address, 0, TEST_SUCCESS)
            self.__datahandler.saveResult(result)
            return TEST_SUCCESS

        # if it doesn't match, means the node has been changing the content
        result = HttpTestResult(exit_node, address, 0, TEST_FAILURE)
        self.__datahandler.saveResult(result)
        tag_file = open(http_tags_dir + `exit_node` + '_' + address_file + '.tags', 'w')
        tag_file.write(psoup.__str__())
        tag_file.close()
        
        return TEST_FAILURE

    def check_openssh(self, address):
        ''' check whether an openssh connection to a given address is molested '''
        # TODO
        #ssh = pyssh.Ssh('username', 'host', 22)
        #ssh.set_sshpath(pyssh.SSH_PATH)
        #response = self.ssh.sendcmd('ls')
        #print response

        return 0 

    def check_openssl(self, address):
        ''' check whether an https connection to a given address is molested '''
        plog('INFO', 'Conducting an ssl test with destination ' + address)

        # an address representation acceptable for a filename 
        address_file = self.__datahandler.safeFilename(address[8:])

        # get the cert via tor

        defaultsocket = socket.socket
        socks.setdefaultproxy(socks.PROXY_TYPE_SOCKS5, tor_host, tor_port)
        socket.socket = socks.socksocket

        cert = self.ssl_request(address)

        # reset the connection method back to direct
        socket.socket = defaultsocket

        exit_node = self.get_exit_node()
        if exit_node == 0 or exit_node == '0' or not exit_node:
            plog('INFO', 'We had no exit node to test, skipping to the next test.')
            return TEST_FAILURE

        # if we got no cert, there was an ssl error
        if cert == 0:
            result = SSLTestResult(exit_node, address, 0, TEST_INCONCLUSIVE)
            self.__datahandler.saveResult(result)
            return TEST_INCONCLUSIVE

        # load the original cert and compare
        # if we don't have the original cert yet, get it
        original_cert = 0
        try:
            cert_file = open(ssl_certs_dir + address_file + '.pem', 'r')
            cert_string = cert_file.read()
            original_cert = crypto.load_certificate(crypto.FILETYPE_PEM, cert_string)
        except IOError:
            plog('INFO', 'Opening a direct ssl connection to ' + address)
            original_cert = self.ssl_request(address)
            if not original_cert:
                plog('ERROR', 'Error getting the correct cert for ' + address)
                return TEST_INCONCLUSIVE
            if original_cert.has_expired():
                plog('ERROR', 'The ssl cert for ' + address + 'seems to have expired. Skipping to the next test...')
                return TEST_INCONCLUSIVE
            cert_file = open(ssl_certs_dir + address_file + '.pem', 'w')
            cert_file.write(crypto.dump_certificate(crypto.FILETYPE_PEM, original_cert))
            cert_file.close()
        except OpenSSL.crypto.Error:
            plog('ERROR', 'There are non-related files in ' + ssl_certs_dir + '. You should probably clean it.')
            return TEST_INCONCLUSIVE
        if not original_cert:
            plog('ERROR', 'Error getting the correct cert for ' + address)
            return TEST_INCONCLUSIVE

        # get an easily comparable representation of the certs
        cert_pem = crypto.dump_certificate(crypto.FILETYPE_PEM, cert)
        original_cert_pem = crypto.dump_certificate(crypto.FILETYPE_PEM, original_cert)

        # in any case we can consider the node looked at
        self.ssl_tested.add(exit_node)

        # if certs match, everything is ok
        if cert_pem == original_cert_pem:
            cert_file = ssl_certs_dir + address_file + '.pem'
            result = SSLTestResult(exit_node, address, cert_file, TEST_SUCCESS)
            self.__datahandler.saveResult(result)
            return TEST_SUCCESS
        
        # if certs dont match, open up a direct connection and update the cert
        plog('INFO', 'Opening a direct ssl connection to ' + address)
        original_cert_new = self.ssl_request(address)
        if original_cert_new == 0:
            plog('ERROR', 'Error getting the correct cert for ' + address)
            result = SSLTestResult(exit_node, address, 0, TEST_INCONCLUSIVE)
            self.__datahandler.saveResult(result)
            return TEST_INCONCLUSIVE

        original_cert_new_pem = crypto.dump_certificate(crypto.FILETYPE_PEM, original_cert_new)

        # compare the old and new cert
        # if certs match, means the exit node has been messing with the cert
        if original_cert_pem == original_cert_new_pem:
            plog('ERROR', 'Exit node ' + `exit_node` + ' seems to be meddling with certificates. (' + address + ')')

            cert_file_name = ssl_certs_dir + address_file + '_' + `exit_node` + '.pem'
            cert_file = open(cert_file_name, 'w')
            cert_file.write(cert_pem)
            cert_file.close()

            result = SSLTestResult(exit_node, address, cert_file_name, TEST_FAILURE)
            self.__datahandler.saveResult(result)
            return TEST_FAILURE

        # if comparsion fails, replace the old cert with the new one
        # XXX: Hrmm, probably should store as a seperate IP file in this case
        # so we don't keep alternating on sites that have round robin
        # DNS and different certs for each IP.. 
        cert_file = open(ssl_certs_dir + address_file + '.pem', 'w')
        cert_file.write(original_cert_new_pem)
        cert_file.close()
            
        # compare the new cert and the node cert
        # if certs match, everything is ok
        if cert_pem == original_cert_new_pem:
            cert_file = ssl_certs_dir + address_file + '.pem'
            result = SSLTestResult(exit_node, address, cert_file, TEST_SUCCESS)
            self.__datahandler.saveResult(result)
            return TEST_SUCCESS

        # if certs dont match, means the exit node has been messing with the cert
        plog('ERROR', 'Exit node ' + `exit_node` + ' seems to be meddling with certificates. (' + address + ')')

        cert_file_name = ssl_certs_dir + address + '_' + `exit_node` + '.pem'
        cert_file = open(cert_file_name, 'w')
        cert_file.write(cert_pem)
        cert_file.close()

        result = SSLTestResult(exit_node, address, cert_file_name, TEST_FAILURE)
        self.__datahandler.saveResult(result)

        return TEST_FAILURE

    def check_smtp(self, address, port=''):
        ''' 
        check whether smtp + tls connection to a given address is molested
        this is done by going through the STARTTLS sequence and comparing server
        responses for the direct and tor connections
        '''

        plog('INFO', 'Conducting an smtp test with destination ' + address)

        defaultsocket = socket.socket
        socks.setdefaultproxy(socks.PROXY_TYPE_SOCKS5, tor_host, tor_port)
        socket.socket = socks.socksocket

        ehlo1_reply = 0
        has_starttls = 0
        ehlo2_reply = 0

        try:
            s = smtplib.SMTP(address, port)
            ehlo1_reply = s.ehlo()[0]
            if ehlo1_reply != 250:
                raise smtplib.SMTPException('First ehlo failed')
            has_starttls = s.has_extn('starttls')
            if not has_starttls:
                raise smtplib.SMTPException('It seems the server doesn\'t support starttls')
            s.starttls()
            # TODO check certs?
            ehlo2_reply = s.ehlo()[0]
            if ehlo2_reply != 250:
                raise smtplib.SMTPException('Second ehlo failed')
        except socket.gaierror, e:
            plog('ERROR', 'A connection error occured while testing smtp at ' + address)
            plog('ERROR', e)
            socket.socket = defaultsocket
            return TEST_INCONCLUSIVE
        except smtplib.SMTPException, e:
            plog('ERROR','An error occured while testing smtp at ' + address)
            plog('ERROR', e)
            return TEST_INCONCLUSIVE
        # reset the connection method back to direct
        socket.socket = defaultsocket 

        # check whether the test was valid at all
        exit_node = self.get_exit_node()
        if exit_node == 0 or exit_node == '0':
            plog('INFO', 'We had no exit node to test, skipping to the next test.')
            return TEST_SUCCESS

        # now directly

        ehlo1_reply_d = 0
        has_starttls_d = 0
        ehlo2_reply_d = 0

        try:
            s = smtplib.SMTP(address, port)
            ehlo1_reply_d = s.ehlo()[0]
            if ehlo1_reply != 250:
                raise smtplib.SMTPException('First ehlo failed')
            has_starttls_d = s.has_extn('starttls')
            if not has_starttls_d:
                raise smtplib.SMTPException('It seems that the server doesn\'t support starttls')
            s.starttls()
            ehlo2_reply_d = s.ehlo()[0]
            if ehlo2_reply_d != 250:
                raise smtplib.SMTPException('Second ehlo failed')
        except socket.gaierror, e:
            plog('ERROR', 'A connection error occured while testing smtp at ' + address)
            plog('ERROR', e)
            socket.socket = defaultsocket
            return TEST_INCONCLUSIVE
        except smtplib.SMTPException, e:
            plog('ERROR', 'An error occurred while testing smtp at ' + address)
            plog('ERROR', e)
            return TEST_INCONCLUSIVE

        print ehlo1_reply, ehlo1_reply_d, has_starttls, has_starttls_d, ehlo2_reply, ehlo2_reply_d

        # compare
        if ehlo1_reply != ehlo1_reply_d or has_starttls != has_starttls_d or ehlo2_reply != ehlo2_reply_d:
            result = SMTPTestResult(exit_node, address, TEST_FAILURE)
            self.__datahandler.saveResult(result)
            return TEST_FAILURE

        result = SMTPTestResult(exit_node, address, TEST_SUCCESS)
        self.__datahandler.saveResult(result)
        return TEST_SUCCESS

    def check_pop(self, address, port=''):
        ''' 
        check whether a pop + tls connection to a given address is molested 
        it is implied that the server reads/sends messages compliant with RFC1939 & RFC2449
        '''

        plog('INFO', 'Conducting a pop test with destination ' + address)

        if not port:
            port = 110

        defaultsocket = socket.socket
        socks.setdefaultproxy(socks.PROXY_TYPE_SOCKS5, tor_host, tor_port)
        socket.socket = socks.socksocket

        capabilities_ok = False
        starttls_present = False
        tls_started = None
        tls_succeeded = None

        try:
            pop = Client(address, port)
        
            # read the server greeting
            server_greeting = pop.readline()

            # get the server capabilities
            pop.writeline('CAPA')
            capabilities = ''
            while 1:
                curr = pop.readline()
                if '+OK' in curr:
                    capabilities_ok = True
                elif curr == '.':
                    break
                elif 'STLS' in curr:
                    starttls_present = True
            
            if not capabilities_ok:
                return TEST_INCONCLUSIVE

            # try to start tls negotiation
            if starttls_present:
                pop.writeline('STLS')

            starttls_started = '+OK' in starttls_response

            # negotiate TLS and issue some request to feel good about it
            # TODO check certs? 
            ctx = SSL.Context(SSL.SSLv23_METHOD)
            c = SSL.Connection(ctx, pop.sock)
            c.set_connect_state()
            c.do_handshake()
            c.send('CAPA' + linebreak)
            
            while tls_succeeded == None:
                line = ''
                char = None
                while char != '\n':
                    char = c.read(1)
                    if not char:
                        break
                    elif char == '.':
                        tls_succeeded = False
                    line += char

                if '-ERR' in line:
                    tls_succeeded = False
                elif '+OK' in line:
                    tls_succeeded = True
                elif not line:
                    tls_succeeded = False

        except socket.error, e: 
            plog('ERROR', 'Connection to ' + address + ':' + port + ' refused')
            plog('ERROR', e)
            socket.socket = defaultsocket
            return TEST_INCONCLUSIVE
        except OpenSSL.SSL.SysCallError, e:
            plog('ERROR', 'Error while negotiating an SSL connection to ' + address + ':' + port)
            plog('ERROR', e)
            socket.socket = defaultsocket
            return TEST_INCONCLUSIVE

        # reset the connection to default
        socket.socket = defaultsocket

        # check whether the test was valid at all
        exit_node = self.get_exit_node()
        if exit_node == 0 or exit_node == '0':
            plog('INFO', 'We had no exit node to test, skipping to the next test.')
            return TEST_SUCCESS

        # do the same for the direct connection

        capabilities_ok_d = False
        starttls_present_d = False
        tls_started_d = None
        tls_succeeded_d = None

        try:
            pop = Client(address, port)
        
            # read the server greeting
            server_greeting = pop.readline()

            # get the server capabilities
            pop.writeline('CAPA')
            capabilities = ''
            while 1:
                curr = pop.readline()
                if '+OK' in curr:
                    capabilities_ok_d = True
                elif curr == '.':
                    break
                elif 'STLS' in curr:
                    starttls_present_d = True
            
            if not capabilities_ok_d:
                return TEST_INCONCLUSIVE

            # try to start tls negotiation
            if starttls_present_d:
                pop.writeline('STLS')

            starttls_started_d = '+OK' in starttls_response

            # negotiate TLS, issue some request to feel good about it
            ctx = SSL.Context(SSL.SSLv23_METHOD)
            c = SSL.Connection(ctx, pop.sock)
            c.set_connect_state()
            c.do_handshake()
            c.send('CAPA' + linebreak)
            
            while tls_succeeded_d == None:
                line = ''
                char = None
                while char != '\n':
                    char = c.read(1)
                    if not char:
                        break
                    elif char == '.':
                        tls_succeeded_d = False
                    line += char

                if '-ERR' in line:
                    tls_succeeded_d = False
                elif '+OK' in line:
                    tls_succeeded_d = True
                elif not line:
                    tls_succeeded_d = False

        except socket.error, e: 
            plog('ERROR', 'Connection to ' + address + ':' + port + ' refused')
            plog('ERROR', e)
            socket.socket = defaultsocket
            return TEST_INCONCLUSIVE
        except OpenSSL.SSL.SysCallError, e:
            plog('ERROR', 'Error while negotiating an SSL connection to ' + address + ':' + port)
            plog('ERROR', e)
            socket.socket = defaultsocket
            return TEST_INCONCLUSIVE

        # compare
        if (capabilities_ok != capabilities_ok_d or starttls_present != starttls_present_d or 
                tls_started != tls_started_d or tls_suceeded != tls_succeeded_d):
            result = POPTestResult(exit_node, address, TEST_FAILURE)
            self.__datahandler.saveResult(result)
            return TEST_FAILURE
        
        result = POPTestResult(exit_node, address, TEST_SUCCESS)
        self.__datahandler.saveResult(result)
        return TEST_SUCCESS

    def check_imap(self, address, port=''):
        ''' 
        check whether an imap + tls connection to a given address is molested 
        it is implied that the server reads/sends messages compliant with RFC3501
        ''' 
        plog('INFO', 'Conducting an imap test with destination ' + address)

        if not port:
            port = 143

        defaultsocket = socket.socket
        socks.setdefaultproxy(socks.PROXY_TYPE_SOCKS5, tor_host, tor_port)
        socket.socket = socks.socksocket
        
        capabilities_ok = None
        starttls_present = None
        tls_started = None
        tls_succeeded = None

        try:
            imap = Client(address, port)

            # read server greeting
            server_greeting = imap.readline()

            # get server capabilities
            imap.writeline('a001 CAPABILITY')
            capabilities = imap.readline() # first line - list of capabilities
            capabilities_ok = 'OK' in imap.readline() # second line - the request status
        
            if not capabilities_ok:
               return TEST_INCONCLUSIVE

            # check if starttls is present
            starttls_present = 'STARTTLS' in capabilities

            if starttls_present:
                imap.writeline('a002 STARTTLS')
                tls_started = 'OK' in imap.readline()

            # negotiate TLS, issue a request to feel good about it
            # TODO check the cert aswell ?
            ctx = SSL.Context(SSL.SSLv23_METHOD)
            c = SSL.Connection(ctx, imap.sock)
            c.set_connect_state()
            c.do_handshake()
            c.send('a003 CAPABILITY' + linebreak)
            
            while tls_succeeded == None:
                line = ''
                char = None
                while char != '\n':
                    char = c.read(1)
                    if not char:
                        break
                    line += char

                if 'Error' in line or 'error' in line:
                    tls_succeeded = False
                elif 'OK' in line:
                    tls_succeeded = True
                elif not line:
                    tls_succeeded = False
    
        except socket.error, e: 
            plog('ERROR', 'Connection to ' + address + ':' + port + ' refused')
            plog('ERROR', e)
            socket.socket = defaultsocket
            return TEST_INCONCLUSIVE
        except OpenSSL.SSL.SysCallError, e:
            plog('ERROR', 'Error while negotiating an SSL connection to ' + address + ':' + port)
            plog('ERROR', e)
            socket.socket = defaultsocket
            return TEST_INCONCLUSIVE
        
        socket.socket = defaultsocket 

        # check whether the test was valid at all
        exit_node = self.get_exit_node()
        if exit_node == 0 or exit_node == '0':
            plog('INFO', 'We had no exit node to test, skipping to the next test.')
            return TEST_SUCCESS

        # do the same for the direct connection
        capabilities_ok_d = None
        starttls_present_d = None
        tls_started_d = None
        tls_succeeded_d = None

        try:
            imap = Client(address, port)

            # read server greeting
            server_greeting = imap.readline()

            # get server capabilities
            imap.writeline('a001 CAPABILITY')
            capabilities = imap.readline() # first line - list of capabilities
            capabilities_ok_d = 'OK' in imap.readline() # second line - the request status

            if not capabilities_ok_d:
                return TEST_INCONCLUSIVE

            # check if starttls is present
            starttls_present_d = 'STARTTLS' in capabilities

            if starttls_present_d:
                imap.writeline('a002 STARTTLS')
                tls_started = 'OK' in imap.readline()

            # negotiate TLS, issue some request to feel good about it
            ctx = SSL.Context(SSL.SSLv23_METHOD)
            c = SSL.Connection(ctx, imap.sock)
            c.set_connect_state()
            c.do_handshake()
            c.send('a003 CAPABILITY' + linebreak)

            while tls_succeeded_d == None:
                line = ''
                char = None
                while char != '\n':
                    char = c.read(1)
                    if not char:
                        break
                    line += char

                if 'Error' in line or 'error' in line:
                    tls_succeeded_d = False
                elif 'OK' in line:
                    tls_succeeded_d = True
                elif not line:
                    tls_succeeded_d = False

        except socket.error, e: 
            plog('ERROR', 'Connection to ' + address + ':' + port + ' refused')
            plog('ERROR', e)
            socket.socket = defaultsocket
            return TEST_INCONCLUSIVE
        except OpenSSL.SSL.SysCallError, e:
            plog('ERROR', 'Error while negotiating an SSL connection to ' + address + ':' + port)
            plog('ERROR', e)
            socket.socket = defaultsocket
            return TEST_INCONCLUSIVE

        # compare
        if (capabilities_ok != capabilities_ok_d or starttls_present != starttls_present_d or 
            tls_started != tls_started_d or tls_succeeded != tls_succeeded_d):
            result = IMAPTestResult(exit_node, address, TEST_FAILURE)
            self.__datahandler.saveResult(result)
            return TEST_FAILURE

        result = IMAPTestResult(exit_node, address, TEST_SUCCESS)
        self.__datahandler.saveResult(result)
        return TEST_SUCCESS

    def check_dns(self, address):
        ''' A basic comparison DNS test. Rather unreliable. '''
        # TODO Spawns a lot of false positives (for ex. doesn't work for google.com). 
        plog('INFO', 'Conducting a basic dns test for destination ' + address)

        ip = tor_resolve(address)

        # check whether the test was valid at all
        exit_node = self.get_exit_node()
        if exit_node == 0 or exit_node == '0':
            plog('INFO', 'We had no exit node to test, skipping to the next test.')
            return TEST_SUCCESS

        ips_d = Set([])
        try:
            results = socket.getaddrinfo(address,None)
            for result in results:
                ips_d.add(result[4][0])
        except socket.herror, e:
            plog('ERROR', 'An error occured while performing a basic dns test')
            plog('ERROR', e)
            return TEST_INCONCLUSIVE

        if ip in ips_d:
            result = DNSTestResult(exit_node, address, TEST_SUCCESS)
            return TEST_SUCCESS
        else:
            plog('ERROR', 'The basic DNS test suspects ' + exit_node + ' to be malicious.')
            result = DNSTestResult(exit_node, address, TEST_FAILURE)
            return TEST_FAILURE

    def check_dns_rebind(self):
        ''' 
        A DNS-rebind attack test that runs in the background and monitors REMAP events
        The test makes sure that external hosts are not resolved to private addresses    
        '''
        plog('INFO', 'Monitoring REMAP events for weirdness')
        self.__dnshandler = DNSRebindScanner(self)
        self.__control.set_event_handler(self.__dnshandler)
        self.__control.set_events([TorCtl.EVENT_TYPE.STREAM], True)

    def http_request(self, address):
        ''' perform a http GET-request and return the content received '''
        request = urllib2.Request(address)
        request.add_header('User-Agent','Mozilla/5.0 (Windows; U; Windows NT 5.1; de; rv:1.8.1) Gecko/20061010 Firefox/2.0')

        content = 0
        try:
            reply = urllib2.urlopen(request)
            content = reply.read()
        except (ValueError, urllib2.URLError):
            plog('ERROR', 'The http-request address ' + address + ' is malformed')
            return 0
        except (IndexError, TypeError):
            plog('ERROR', 'An error occured while negotiating socks5 with Tor')
            return 0

        return content

    def ssh_request(self):
        pass

    def ssl_request(self, address):
        ''' initiate an ssl connection and return the server certificate '''
        
        # drop the https:// prefix if present (not needed for a socket connection)
        if address[:8] == 'https://':
            address = address[8:]
    
        # specify the context
        ctx = SSL.Context(SSL.SSLv23_METHOD)
        ctx.set_verify_depth(1)

        # ready the certificate request
        request = crypto.X509Req()

        # open an ssl connection
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        c = SSL.Connection(ctx, s)
        c.set_connect_state()
       
        try:
            c.connect((address, 443))
            c.send(crypto.dump_certificate_request(crypto.FILETYPE_PEM,request))
        except socket.error, e:
            plog('ERROR','An error occured while opening an ssl connection to ' + address)
            plog('ERROR', e)
            return 0
        except (IndexError, TypeError):
            plog('ERROR', 'An error occured while negotiating socks5 with Tor')
            return 0
        
        # return the cert
        return c.get_peer_certificate()

# some helpful methods

def load_wordlist(file):
    ''' load a list of strings from a file (which contains words separated by newlines) '''
    plog('INFO', 'Loading the wordlist')
    
    wordlist = []
    fh = None
    try:
        fh = open(file, 'r')
    except IOError, e:
        plog('ERROR', 'Reading the wordlist file failed.')
        plog('ERROR', e)
    
    try:
        for line in fh:
            wordlist.append(line[:-1]) # get rid of the linebreaks
    finally:
        fh.close()

    return wordlist

def get_urls(wordlist, filetypes=['any'], results_per_type=5, protocol='any', g_results_per_page=10):
    ''' 
    construct a list of urls based on the wordlist, filetypes and protocol. 
    
    Note: since we currently use google, which doesn't index by protocol,
    searches for anything but 'any' could be rather slow
    '''
    plog('INFO', 'Searching google for relevant sites...')

    urllist = []
    for filetype in filetypes:
        type_urls = []

        while len(type_urls) < results_per_type:
            query = random.choice(wordlist)
            if filetype != 'any':
                query += ' filetype:' + filetype
            if protocol != 'any':
                query += ' allinurl:' + protocol # this isn't too reliable, but we'll re-filter results later
            #query += '&num=' + `g_results_per_page` 

            # search google for relevant pages
            # note: google only accepts requests from idenitified browsers
            # TODO gracefully handle the case when google doesn't want to give us result anymore
            host = 'www.google.com'
            params = urllib.urlencode({'q' : query})
            headers = {'User-Agent' : 'Mozilla/5.0 (Windows; U; Windows NT 5.1; de; rv:1.8.1) Gecko/20061010 Firefox/2.0'}
            search_path = '/search' + '?' + params

            connection = None
            response = None

            try:
                connection = httplib.HTTPConnection(host)
                connection.request("GET", search_path, {}, headers)
                response = connection.getresponse()
                if response.status != 200:
                    raise Exception(response.status, response.reason)
            except socket.gaierror, e:
                plog('ERROR', 'Connection to google.com failed')
                plog('ERROR', e)
                return list(Set(urllist))

            content = response.read()
            links = SoupStrainer('a')
            soup = BeautifulSoup(content, parseOnlyThese=links)
            
            # get the links and do some additional filtering
            for link in soup.findAll('a', {'class' : 'l'}):
                url = link['href']
                if (protocol != 'any' and url[:len(protocol)] != protocol or 
                        filetype != 'any' and url[-len(filetype):] != filetype):
                    pass
                else:
                    type_urls.append(link['href'])
        
        if type_urls > results_per_type:
            type_urls = random.sample(type_urls, results_per_type) # make sure we don't get more urls than needed
        urllist.extend(type_urls)
         
    return list(Set(urllist))

def tor_resolve(address):
    ''' performs a DNS query explicitly via tor '''
    return commands.getoutput("tor-resolve " + address)

def int2bin(n):
    '''
    simple decimal -> binary conversion, needed for comparing IP addresses 
    '''
    n = int(n)
    if n < 0:
        raise ValueError, "Negative values are not accepted."
    elif n == 0:
        return '0'
    else:
        bin = ''
        while n > 0:
            bin += str(n % 2)
            n = n >> 1
        return bin[::-1]
#
# main logic
#
def main(argv):
    # make sure we have something to test for
    if len(argv) < 2:
        print ''
        print 'Please provide at least one test option:'
        print '--ssl (~works)'
        print '--http (gives some false positives)'
        print '--ssh (doesn\'t work yet)'
        print '--smtp (~works)'
        print '--pop (~works)'
        print '--imap (~works)'
        print '--dns (a basic test, not really reliable)'
        print '--dnsrebind (works with the ssl test)'
        print '--policies (~works)'
        print ''
        sys.exit(0)

    opts = ['ssl','http','ssh','smtp','pop','imap','dns','dnsrebind','policies']
    flags, trailer = getopt.getopt(argv[1:], [], opts)
    
    # get specific test types
    do_ssl = ('--ssl','') in flags
    do_http = ('--http','') in flags
    do_ssh = ('--ssh','') in flags
    do_smtp = ('--smtp','') in flags
    do_pop = ('--pop','') in flags
    do_imap = ('--imap','') in flags
    do_dns_basic = ('--dns','') in flags
    do_dns_rebind = ('--dnsrebind','') in flags
    do_consistency = ('--policies','') in flags

    # load the wordlist to search for sites lates on
    wordlist = load_wordlist(wordlist_file)

    # initiate the scanner
    scanner = ExitNodeScanner()

    # initiate the passive dns rebind attack monitor
    if do_dns_rebind:
        scanner.check_dns_rebind()

    # check for sketchy exit policies
    if do_consistency:
        scanner.check_all_exits_port_consistency()

    # maybe only the consistency test was required
    if not (do_ssl or do_http or do_ssh or do_smtp or do_pop or do_imap or do_dns_basic):
        plog('INFO', 'Done.')
        sys.exit(0)

    # declare some variables and assign values if neccessary
    ssl_nodes = http_nodes = ssh_nodes = smtp_nodes = pop_nodes = imap_nodes = dns_nodes = []
    ssl_nodes_n = http_nodes_n = ssh_nodes_n = smtp_nodes_n = pop_nodes_n = imap_nodes_n = dns_nodes_n = 0
    ssl_urls = http_urls = ssh_urls = smtp_urls = pop_urls = imap_urls = dns_urls = []
    ssl_fail = http_fail = ssh_fail = smtp_fail = pop_fail = imap_fail = imap_urls = 0

    if do_ssl:
        ssl_nodes = scanner.get_nodes_for_port(443)
        ssl_nodes_n = len(ssl_nodes)
        # the search for https urls is yet too slow
        ssl_urls =  ['https://mail.google.com', 'https://addons.mozilla.org', 'https://www.fastmail.fm'] 
        ssl_fail = len(scanner.ssl_fail)

        if len(ssl_urls) == 0:
            plog('ERROR', 'No urls specified for ssl testing.')
            do_ssl = False

    if do_http:
        http_nodes = scanner.get_nodes_for_port(80)
        http_nodes_n = len(http_nodes)
        http_urls = get_urls(wordlist, protocol='http', results_per_type=10, g_results_per_page=20)
        http_fail = len(scanner.http_fail)

        if len(http_urls) == 0:
            plog('ERROR', 'No urls specified for http testing.')
            do_http = False

    if do_ssh:
        ssh_nodes = scanner.get_nodes_for_port(22)
        ssh_nodes_n = len(ssh_nodes)
        ssh_urls = []
        ssh_fail = len(scanner.ssh_fail)

        if len(ssl_urls) == 0:
            plog('ERROR', 'No urls specified for ssh testing.')
            do_ssh = False

    if do_smtp:
        smtp_urls = [('smtp.gmail.com','587')]

        if len(smtp_urls) == 0:
            plog('ERROR', 'No urls specified for smtp testing.')
            do_smtp = False

    if do_pop:
        pop_urls = []

        if len(pop_urls) == 0:
            plog('ERROR', 'No urls specified for pop testing.')
            do_pop = False

    if do_imap:
        imap_urls = []

        if len(imap_urls) == 0:
            plog('ERROR', 'No urls specified for imap testing.')
            do_imap = False

    if do_dns_basic:
        dns_urls = []

        if len(dns_urls) == 0:
            plog('ERROR', 'No urls specified for dns testing.')
            do_dns_basic = False

    # maybe no tests could be initialized
    if not (do_ssl or do_http or do_ssh or do_smtp or do_pop or do_imap or do_dns_basic):
        plog('INFO', 'Done.')
        sys.exit(0)

    # start testing
    while 1:  
        
        # https test  
        if do_ssl:
            candidates = [x for x in ssl_nodes if ('$' + `x.idhex`) not in scanner.ssl_tested]
            if len(candidates) > 0:
                current_exit = random.choice(candidates)
                scanner.set_new_exit(current_exit.idhex)
            
            scanner.get_new_circuit()
            ssl_site = random.choice(ssl_urls)
            scanner.check_openssl(ssl_site)
            
            ssl_tested_n = len(scanner.ssl_tested)
            if ssl_nodes_n > ssl_tested_n:
                plog('INFO', 'Nodes ssl-tested: ' + `ssl_tested_n` + '/' + `ssl_nodes_n`
                    + ' (~' + `((ssl_tested_n * 100) / ssl_nodes_n)` + '%)')
        
        # http test
        if do_http:
            candidates = [x for x in http_nodes if ('$' + `x.idhex`) not in scanner.http_tested]
            if len(candidates) > 0 :
                current_exit = random.choice(candidates)
                scanner.set_new_exit(current_exit.idhex)
            
            scanner.get_new_circuit()
            http_site = random.choice(http_urls)
            scanner.check_http(http_site)

            http_tested_n = len(scanner.http_tested)
            if http_nodes_n > http_tested_n:
                plog('INFO', 'Nodes http-tested: ' + `http_tested_n` + '/' + `http_nodes_n`
                    + ' (~' + `((http_tested_n * 100) / http_nodes_n)` + '%)')
        
        # ssh test
        if do_ssh:
            candidates = [x for x in ssh_nodes if ('$' + `x.idhex`) not in scanner.ssh_tested]
            if len(candidates) > 0:
                current_exit = random.choice(candidates)
                scanner.set_new_exit(current_exit.idhex)
                
            scanner.get_new_circuit()
            ssh_site = random.choice(ssh_urls)
            scanner.check_ssh(ssh_site)
 
            ssh_tested_n = len(scanner.ssh_tested)
            if ssh_nodes_n > ssh_tested_n:
                plog('INFO', 'Nodes ssh-tested: ' + `ssh_tested_n` + '/' + `ssh_nodes_n`
                    + '(~' + `((ssh_tested_n * 100) / ssh_nodes_n)` + '%')

        # smtp test
        if do_smtp:
            scanner.get_new_circuit()
            smtp_site = random.choice(smtp_urls)
            scanner.check_smtp(smtp_site[0], smtp_site[1])

        # pop test
        if do_pop:
            scanner.get_new_circuit()
            pop_site = random.choice(pop_urls)
            scanner.check_pop(pop_site[0], pop_site[1])

        # imap test
        if do_imap:
            scanner.get_new_circuit()
            imap_site = random.choice(imap_urls)
            scanner.check_imap(imap_site[0], imap_site[1])

        #
        # managing url lists
        # if we've been having too many false positives lately, get a new target list
        # 

        if do_http and len(scanner.http_fail) - http_fail >= len(http_urls):
            http_urls = get_urls(wordlist, protocol='http', results_per_type=10, g_results_per_page=20)
            http_fail = len(scanner.http_fail)
        
#
# initiate the program
#
if __name__ == '__main__':
    try:
        main(sys.argv)
    except KeyboardInterrupt:
        plog('INFO', "Ctrl + C was pressed. Exiting ... ")
    except Exception, e:
        plog('ERROR', "An unexpected error occured.")
        plog('ERROR', e)
