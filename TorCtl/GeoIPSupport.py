#!/usr/bin/python

import struct
import socket
import GeoIP
import TorCtl

from TorUtil import plog

# GeoIP data object: choose database here
geoip = GeoIP.new(GeoIP.GEOIP_STANDARD)
#geoip = GeoIP.open("./GeoLiteCity.dat", GeoIP.GEOIP_STANDARD)

# Continent class
class Continent:
  def __init__(self, continent_code):
    self.code = continent_code 
    self.countries = []

  def contains(self, country_code):
    return country_code in self.countries

# Setup the continents
africa = Continent("AF")
africa.countries = ["AO","BF","BI","BJ","BV","BW","CD","CF","CG","CI","CM","CV","DJ","DZ",
                    "EG","EH","ER","ET","GA","GH","GM","GN","GQ","GW","HM","KE","KM","LR",
		    "LS","LY","MA","MG","ML","MR","MU","MW","MZ","NA","NE","NG","RE","RW",
		    "SC","SD","SH","SL","SN","SO","ST","SZ","TD","TF","TG","TN","TZ","UG",
		    "YT","ZA","ZM","ZR","ZW"]

asia = Continent("AS")
asia.countries = ["AP","AE","AF","AM","AZ","BD","BH","BN","BT","CC","CN","CX","CY","GE",
                  "HK","ID","IL","IN","IO","IQ","IR","JO","JP","KG","KH","KP","KR","KW",
		  "KZ","LA","LB","LK","MM","MN","MO","MV","MY","NP","OM","PH","PK","PS",
		  "QA","RU","SA","SG","SY","TH","TJ","TM","TP","TR","TW","UZ","VN","YE"]

europe = Continent("EU")
europe.countries = ["EU","AD","AL","AT","BA","BE","BG","BY","CH","CZ","DE","DK","EE","ES",
                    "FI","FO","FR","FX","GB","GI","GR","HR","HU","IE","IS","IT","LI","LT",
		    "LU","LV","MC","MD","MK","MT","NL","NO","PL","PT","RO","SE","SI","SJ",
		    "SK","SM","UA","VA","YU"]

oceania = Continent("OC")
oceania.countries = ["AS","AU","CK","FJ","FM","GU","KI","MH","MP","NC","NF","NR","NU","NZ",
                     "PF","PG","PN","PW","SB","TK","TO","TV","UM","VU","WF","WS"]

north_america = Continent("NA")
north_america.countries = ["CA","MX","US"]

south_america = Continent("SA")
south_america.countries = ["AG","AI","AN","AR","AW","BB","BM","BO","BR","BS","BZ","CL","CO",
                            "CR","CU","DM","DO","EC","FK","GD","GF","GL","GP","GS","GT","GY",
			    "HN","HT","JM","KN","KY","LC","MQ","MS","NI","PA","PE","PM","PR",
			    "PY","SA","SR","SV","TC","TT","UY","VC","VE","VG","VI"]

# List of continents
continents = [africa, asia, europe, north_america, oceania, south_america]

# Perform country -- continent mapping
def get_continent(country_code):
  for c in continents:
    if c.contains(country_code):
      return c.code
  plog("WARN", country_code + " is not on any continent")
  return None

# Get the country code out of a GeoLiteCity record (not used)
def get_country_from_record(ip):
  record = geoip.record_by_addr(ip)
  if record != None:
    return record['country_code']

# Router class extended to GeoIP
class GeoIPRouter(TorCtl.Router):  
  def __init__(self, router):
    self.__dict__ = router.__dict__
    # Select method to get the country_code here
    self.country_code = geoip.country_code_by_addr(self.get_ip_dotted())
    #self.country_code = get_country_from_record(self.get_ip_dotted())    
    if self.country_code == None: 
      plog("WARN", self.nickname + ": Country code not found")
      self.continent = None
    else: self.continent = get_continent(self.country_code)

  # Convert long int back to dotted quad string
  def get_ip_dotted(self):
    return socket.inet_ntoa(struct.pack('>I', self.ip))

class GeoIPConfig:
  """ Class to configure GeoIP-based path building """		    
  def __init__(self, unique_countries, entry_country, exit_country, max_crossings, excludes):    
    # TODO: Somehow ensure validity of the configuration
    
    # Do not use a country twice in a route 
    # [True --> unique, False --> same or None --> pass] 
    self.unique_countries = unique_countries
    
    # entry in entry_country [single country code or None]
    self.entry_country = entry_country
    # exit in exit_country [single country code or None]
    self.exit_country = exit_country
    
    # Configure max continent crossings in one path 
    # [integer number 0-n or None --> ContinentJumper/UniqueContinent]
    self.max_crossings = max_crossings
    
    # List of countries to not use in routes 
    # [(empty) list of country codes or None]
    self.excludes = excludes