__author__ = 'gokhan.karakas'
import os, optparse
import socket, httplib, urllib
import subprocess
import sys, getopt
import time, datetime
from xml.dom.minidom import parseString
import base64

parser = optparse.OptionParser(usage='python %prog -i IP -x Nexpose IP -u Nexpose username -p Nexpose password or python %prog -l file with IPs -x Nexpose IP -u Nexpose username -p Nexpose password', prog=sys.argv[0],)

parser.add_option('-i','--ip',action="store", help="IP to scan. REQUIRED", type="string", dest="ip")
parser.add_option('-l', '--list',action="store", help="List of IPs to scan. REQUIRED", type="string", dest="iplist")
parser.add_option('-x', '--nexpose_ip',action="store", help="IP address of Nexpose scanner. REQUIRED", type="string", dest="nexpose_ip")
parser.add_option('-u', '--nexpose_user',action="store", help="Username for Nexpose user. REQUIRED", type="string", dest="nexpose_user")
parser.add_option('-p', '--nexpose_password',action="store", help="Password for Nexpose user. REQUIRED", type="string", dest="nexpose_password")
parser.add_option('-v', '--verbose',action="store", help="Turn on verbose output. Must be set to on.", dest="ver")
parser.add_option('-o', '--out',action="store", help="Output File. Default results will be written to output.pdf.", type="string", dest="outfile", default="output.pdf")

options, args = parser.parse_args()

#grab the options into variables

ipvar = options.ip
listvar=options.iplist
vervar = options.ver
outputvar = options.outfile
nexposeip=options.nexpose_ip
nexposeuser=options.nexpose_user
nexposepassword=options.nexpose_password

#Test for required Input

regchecka=0
regcheckb=0

if(ipvar is None):
    regchecka =1

if(listvar is None):
    regcheckb = 1


if(regchecka ==1 and regcheckb==1):
    print "-i or -l mandatory option is missing.\n"
    parser.print_help()
    exit(-1)

if(regchecka ==0 and regcheckb==0):
    print "Only one required argument. Use eigther -i or -l.\n"
    parser.print_help()
    exit(-1)

if(nexposeip is None):
    print "Nexpose IP is missing. -x is needed.\n"
    parser.print_help()
    exit(-1)

if(nexposeuser is None):
    print "Nexpose Scanner Username is missing. -u is needed.\n"
    parser.print_help()
    exit(-1)

if(nexposepassword is None):
    print "Nexpose Scanner Password is missing. -p is needed.\n"
    exit(-1)

#End of user input testing


#varilables to keep track of
#we define

templateid = "full-audit"
report_name= outputvar

#Nexpose Defined

session_id=""
site_id=""
scan_id=""
#end of variables


#make the web calls to nexpose

#login call to nexpose

c = httplib.HTTPSConnection(nexposeip, 3780)
xml_request ="""<LoginRequest sync-id="%s" password="%s" />""" % (nexposeuser, nexposepassword)
headers = {"Contenet-type":"text/xml"}
print "Logging into Nexpose"

try:
    c.request("POST", "/api/1.2/xml", xml_request, headers)
except:
    print "Problem making the login call"
    exit(-1)

response = c.getresponse()
if (vervar == "on"):
    print "Response status %s , Response reason: %s " % (response.status,response.reason)
data = response.read()

if(vervar == "on"):
    print "Data recieved: %s" % data

# take the data received and look for what we need

dom = parseString(data)
try:
    xmlTag= dom.getElementsByTagName("LoginResponse")[0]
    successvalue = xmlTag.getAttribute("success")
    if (vervar == "on"):
        print "Success value: %s" % successvalue
    session_id = xlmTag.getAttribute("session-id")
    if(vervar == "on"):


https://github.com/lordsaibat/nexpose_python_client/blob/master/nexpose.py