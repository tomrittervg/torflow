#!/usr/bin/python
#
# Standard SoaT Sauce
#
# This file is ordered from most user-servicable to least. 
# Don't be sad if you don't know how to change the stuff
# at the bottom. You probably shouldn't.

import sys
sys.path.append("../../")
try:
    from TorCtl.PathSupport import *
except ImportError:
    from os import getcwd, path
    print "TorCtl not found in %s. Did you run torflow.git/add_torctl.sh?" % path.abspath(getcwd()+'../..')
    print "Exiting..."
    exit() 

from soat import BeautifulSoup

# Keywords from these files are used  when searching for 'random' urls 
# for testing. They can be the same file, or different files.
filetype_wordlist_file = './wordlist.txt';
html_wordlist_file = './wordlist.txt';
ssl_wordlist_file = './wordlist.txt';

# Number of SSL hosts to scan
num_ssl_hosts = 10

# Number of HTML urls to scan
num_html_urls = 10

# Maximum number of searches per filetype before giving up
max_search_retry = 3

# Hrmm.. Too many of these and Google really h8s us..
scan_filetypes = ['pdf','doc','html']

# Urls to scan for each filetype
urls_per_filetype = 2

# Avoid vmware images+isos plz. Nobody could possibly have the patience
# to download anything much larger than 256k over Tor anyways ;)
max_content_size = 256*1024 

# Bind refetches of docuements to a specific source IP.
# Useful for eliminating false positives that arise
# from IP-based identifiers encoded in content
refetch_ip = None
#refetch_ip = "4.4.4.4"

# Email settings for emailing scanned results:
mail_server = "127.0.0.1"
# Email authentication
# If your smtp server requires a username and password, set
# mail_auth to True. In this case, one of mail_tls or
# mail_starttls must also be set to True.
mail_auth = False
mail_user = "soat@fscked.org"
mail_password = "password"
mail_tls = False # Requires Python >= 2.6
mail_starttls = False
mail_from_email = "Tor Exit Scanner <"+mail_user+">"
mail_to_email = ["Tor Exit Scanner List <tor-exitscanner@lists.torproject.org>"]

# What percentage of tested nodes must disagree with our local fetches before
# we ignore the target site/url
max_exit_fail_pct = 5

# What percentage of tested nodes must get a non 2xx response 
# (including timeouts and DNS resolution failures) to a request
# before we ignore the target site/url
# XXX: current unused
max_httpcode_fail_pct = 10

# What percentage of tested nodes must get a bad http response
# or other connection issue (including timeouts and DNS resolution 
# failures) to a request # before we ignore the target site/url
max_connect_fail_pct = 10

# What percentage of tests can fail that differ between all 3 fetches
# fetches (Tor and two non-tor), AFTER applying HTML false positive filters
max_dynamic_fail_pct = 5

# We fetch more target sites/urls if discarding them causes us to fall
# below this many:
min_targets = 10

# How many times each node should be tested before removing it from 
# a run loop (can be overriden on command line)
num_tests_per_node = 5
num_rescan_tests_per_node = 5

# Number of timeouts before we consider a node failed.
num_timeouts_per_node = 4

# Number of resolution errors before we consider a node failed.
num_dnsfails_per_node = 4

# Number of misc connection errors before we consider a node failed
num_connfails_per_node = 2

# Rescan failures upon finishing the run loop. 
# FIXME: This does have the downside that we do NOT prune excessively 
# dynamic URLs during this loop, and so false positives may accumulate...
rescan_at_finish = True

# Should we restart scanning from the beginning at the finish?
restart_at_finish = True

# Kill fetches if they drop below 100bytes/sec on average
min_rate=100

# Give up if a socket read takes more than this long to complete
read_timeout=120.0

# Ignore nodes advertising no bandwidth.... (hackish)
min_node_bw=1024

firefox_headers = [
  ('User-Agent','Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US; rv:1.9.0.7) Gecko/2009021910 Firefox/3.0.7'),
  ['Accept','text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'],
  ('Accept-Language',"en-us,en;q=0.5"),
  ('Accept-Encoding',"gzip,deflate"),
  ('Accept-Charset', "ISO-8859-1,utf-8;q=0.7,*;q=0.7"),
  ('Keep-Alive',"300"),
  ('Connection',"keep-alive")
]
image_accept_hdr = "image/png,image/*;q=0.8,*/*;q=0.5"
script_accept_hdr = "*/*"

# Probability we select a random url for our referer and track referer 
# urls
referer_chance_pct = 50

# Where to store our scraping cookies
search_cookie_file="./search_cookies.lwp"

# Search mode. 
# Leave these maps alone. Change the default_search_mode variable 
# to what you want.
# XXX: Make a bing search mode and a DuckDuckGo search mode

#Yahoo is no longer supported because they make it difficult to scrape their results
#yahoo_search_mode = {"host" : "search.yahoo.com/search", "query":"p", "filetype": "vf:", \
#                      "inurl":None, "class":"yschttl", "realtgt":"ourl", "useragent":False, \
#                      "extra":[]}

google_search_mode = {"host" : "www.google.com/search", "query":"q", "filetype":"filetype:", \
                       "inurl":"inurl:", "class" : "l", "realtgt":"href", "useragent":True, \
                       "extra":[]}

ixquick_search_mode = {"host" : "ixquick.com/do/metasearch.pl", "query":"all_terms", "filetype":"url:.", \
                      "inurl":"url:", "class" : "title2", "realtgt":"href", "useragent":False, \
                      "extra":[("prfh","disable_family_filterEEE1N1Nnum_of_resultsEEE50N1Ndisable_video_family_filterEEE1N1N")]}
 

default_search_mode = google_search_mode
#default_search_mode = ixquick_search_mode

# Regex of characters we consider unsafe to write to the filesystem
unsafe_filechars = "[^a-zA-Z0-9-\.+]"

# non-public IPv4 address ranges network portions
# refer to: www.iana.org/assignments/ipv4-address-space, www.iana.org/assignments/multicast-addresses
ipv4_nonpublic = [
  '00000000',     # default route and its network: 0.0.0.0/8
  '00001010',     # private 10.0.0.0/8
  '01111111',     # loopback 127.0.0.0/8
  '1010100111111110', # link-local 169.254.0.0/16
  '101011000001',   # private 172.16.0.0/12
  '1100000010101000', # private 192.168.0.0/16
  '111'         # multicast & experimental 224.0.0.0/3
]

# The BeautifulSoup Parser we use.
TheChosenSoup = BeautifulSoup

# HTTP Headers to ignore for the header check. Basically we are mainly
# interested in only a few headers (like content-disposition and link)
# that can be used to detect us or alter browser behavior), but 
# better to exclude known-good than check for known-bad (when possible)
ignore_http_headers = ['content-type', 'date', 'set-cookie', 'x-.*', 'via',
'etag', 'vary', 'content-length', 'server', 'content-language',
'last-modified', 'proxy-connection', 'content-encoding', 'age',
'transfer-encoding', 'expires', '~*', '-*', 'connection']

# Tags and attributes to check in the http test.
# The general idea is to grab tags with attributes known
# to either hold script, or cause automatic network actvitity
# Note: the more we add, the greater the potential for false positives...  
tags_to_check = ['a', 'object', 'form', 'frame', 'iframe', 'input',
                 'script', 'style']
tags_preserve_inner = ['script','style']

attrs_with_raw_script = [
'onclick', 'ondblclick', 'onmousedown', 'onmouseup', 'onmouseover',
'onmousemove', 'onmouseout', 'onkeypress', 'onkeydown', 'onkeyup', 'onload',
'onunload', 'onabort', 'onerror', 'onresize', 'onscroll', 'onselect',
'onchange', 'onsubmit', 'onreset'
]

attrs_to_check = ['href', 'src', 'style']
attrs_to_check.extend(attrs_with_raw_script)
attrs_to_check_map = {}
for __a in attrs_to_check: attrs_to_check_map[__a]=1
attrs_with_raw_script_map = {}
for __a in attrs_with_raw_script: attrs_with_raw_script_map[__a]=1

attrs_to_prune = ['alt', 'label', 'prompt' 'standby', 'summary', 'title',
                  'abbr']

# For recursive fetching of urls:
tags_to_recurse = ['a', 'frame', 'iframe', 'link', 'object', 'script']
recurse_html = ['frame', 'iframe', 'layer', 'ilayer']

recurse_script = ['script']
attrs_to_recurse = ['href', 'src']
recurse_image = []

html_schemes = ['http']

script_mime_types = [".*text/javascript.*", ".*application/javascript.*"]
html_mime_types = ['.*application/xhtml+xml', '.*text/html.*']

# Ports to test in the exit policy consistency test
ports_to_check = [
  ["pop", ExitPolicyRestriction('255.255.255.255', 110), "pops", ExitPolicyRestriction('255.255.255.255', 995)],
  ["imap", ExitPolicyRestriction('255.255.255.255', 143), "imaps", ExitPolicyRestriction('255.255.255.255', 993)],
  ["telnet", ExitPolicyRestriction('255.255.255.255', 23), "ssh", ExitPolicyRestriction('255.255.255.255', 22)],
  ["smtp", ExitPolicyRestriction('255.255.255.255', 25), "smtps", ExitPolicyRestriction('255.255.255.255', 465)],
  ["http", ExitPolicyRestriction('255.255.255.255', 80), "https",
ExitPolicyRestriction('255.255.255.255', 443)],
  ["email", NodeRestrictionList([
ExitPolicyRestriction('255.255.255.255',110),
ExitPolicyRestriction('255.255.255.255',143)
]),
"secure email",
OrNodeRestriction([
ExitPolicyRestriction('255.255.255.255',995),
ExitPolicyRestriction('255.255.255.255',993),
ExitPolicyRestriction('255.255.255.255',465),
ExitPolicyRestriction('255.255.255.255',587)
])],
  ["plaintext", AtLeastNNodeRestriction([
ExitPolicyRestriction('255.255.255.255',110),
ExitPolicyRestriction('255.255.255.255',143),
ExitPolicyRestriction('255.255.255.255',23),
ExitPolicyRestriction('255.255.255.255',21),
ExitPolicyRestriction('255.255.255.255',80)
#ExitPolicyRestriction('255.255.255.255',25),
], 4),
"secure",
OrNodeRestriction([
ExitPolicyRestriction('255.255.255.255',995),
ExitPolicyRestriction('255.255.255.255',993),
ExitPolicyRestriction('255.255.255.255',22),
ExitPolicyRestriction('255.255.255.255',465),
ExitPolicyRestriction('255.255.255.255',587),
ExitPolicyRestriction('255.255.255.255',443)
])]
]

# Data locations
# XXX: I advise against changing these.. some of them are derived on the fly
# We still need to unify how that is handled..
data_dir = './data/'
soat_dir = './data/soat/'
ssl_certs_dir = soat_dir + 'ssl/certs/'
ssl_falsepositive_dir = soat_dir + 'ssl/falsepositive/'
http_data_dir = soat_dir + 'http/'
http_content_dir = soat_dir + 'http/content/'
http_failed_dir = soat_dir + 'http/failed/'
http_inconclusive_dir = soat_dir + 'http/inconclusive/'
http_falsepositive_dir = soat_dir + 'http/falsepositive/'

