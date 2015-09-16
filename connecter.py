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
        print 'success value %s' % successvalue
    session_id=xlmTag.getAttribute('session-id')
    if(vervar=='on'):
        print 'session-id: %s' % session_id
except:
    print 'Login Response exception occured'
    exit(-1)

#check success

if successvalue==0 :
    print 'Login Error\n'
    exit(-1)

#create the site in Nexpose
nexpose_site_name= datetime.datetime.now().strftime('%y-%m-%d-%H-%M') + '_Nexpose_test'
host_string=''

if (regchecka ==0):
    host_string= '<host>%s</host>' % ipvar

if(regcheckb==0):
    of= open(listvar, 'r').readlines()
    list=[]
    for lines in of:
        ip=lines.strip()
        hostag='<host>%s</host>' % ip
        list.append(hostag)
    hosts_string=list

#building site creation request
xml_request = """<SiteSaveRequest session-id='%s'>""" % session_id + """<Site id+"-1" name="%s" description="Quick Scan">""" % nexpose_site_name + """<Hosts>""" +str(hosts_string) +"""</Hosts> <Credentials></Credentials><Alerting></Alerting> <ScanConfig ConfigID="-1" name="Special Example" templateID="full-audit"></ScanConfig></Site> </SiteSaveRequest>"""


headers = {"Content-type": "text/xml"}

print 'Creating the site'

try:
    c.request("POST", "/api/1.2/xml", xml_request, headers)
    response = c.getresponse()
except:
    print "Problem making the SiteSaveRequest."
    exit(-1)

if(vervar="on"):
    print "Response status: %s Response reason: %s" % (response.status, response.reason)
data = response.read()

if(vervar="on"):
    print('Data received: %s' % data)

#take the data received and look for what we need

dom= parseString(data)
try:
    xmlTag= dom.getElementsByTagName("SiteSaveResponse")[0]
    successvalue=xmlTag.getAttribute("success")
    site_id=xmlTag.getAttribute("site-id")
except:
    print "Results from the SiteSaveResponse returned unexpected result"
    exit(-1)

#check success
if(successvalue==0):
    print 'Site Creation Error\n'
    exit(-1)

#wait for site to be created

time.sleep(5)

#scan site request

xml_request="""<SiteScanRequest session-id="%s" site-id="%s"></SiteScanRequest>""" % (session_id, site_id)
headers= {"Content-type":"text/xml"}

print "Telling Nexpose to scan the site created"

try:
    c.request("POST", "/api/1.2/xml", xml_request, headers)
    response=c.getresponse()
except:
    print "Problem making the SiteScanRequest"
    exit(-1)

if(vervar="on"):
    print "Response status: %s, Response reason: %s" % (response.status, response.reason)
    data=response.read()
if(vervar="on"):
    print "Data received: %s" % data


# take the data received and look for what we need
dom = parseString(data)
try:
    xmlTag=dom.getElementsByTagName("SiteScanResponse")[0]
    successvalue=xmlTag.getAttribute("succes")
except:
    print "Results from the SiteSaveResponse returned an unexpected result"
    exit(-1)

#check success
if(successvalue==0):
    print "Site scan error Error\n"
    exit(-1)

#Take scan-id and engine-id
#take the data received and look for what we need

try:
    dom = parseString(data)
    xmlTag= dom.getElementsByTagName("SiteScanResponse")[0]
    successvalue=xmlTag.getAttribute("success")

    xmlTag2 = dom.getElementsByTagName("Scan")[0]
    scan_id = xmlTag2.getAttribute("scan-id")
    engine_id = xmlTag2.getAttribute("engine-id")
except:
    print 'Results from the SiteSaveResponse returned an unexpected result'
    exit(-1)


#check success
if(successvalue==0):
    print 'Site scan error Error\n'
    exit(-1)

#test if scan is complete

exception= ''
status='running'
while(exception=="" and status=="running"):
    #reset status
    status="stopped"
    exception=""
    successvalue=""

    xml_request ="""<ScanStatusRequest session-id="%s" scan-id="%s"></ScanStatusRequest>""" % (session_id, scan_id)
    headers={"Content-type":"text/xml"}
    print "Checking on the status of the scan"

    c=httplib.HTTPSConnection(nexposeip, 3780)
    try:
        c.request("POST", "/api/1.2/xml", xml_request, headers)
        response=c.getresponse()
        if(vervar=='on'):
            print "Response status: %s, Response reason: %s" % (response.status, response.reason)
        data = response.read()
        if  (vervar='on'):
            print 'Data recieved: %s ' % data
    except:
        print "ScanStatusRequest exception"
        status= "stopped"
        exception='stop'
        pass

#take the data received and look for what we need
    dom = parseString(data)
    try:
        xmlTag = dom.getElementsByTagName("ScanStatusResponse")[0]
        successvalue=xmlTag.getAttribute("success")
        status= xmlTag.getAttribute("status")
    except:
        print "Result from the ScanStatusResponse returned an unexpected result"
        exit(-1)

    if(dom==""):
        print "No data"
        status="stopped"

    #check success
    if (successvalue==0):
        print "error scanning\n"
        exit(-1)

    #check exception
    #print exception
    if (exception == "stopped"):
        status = "stop"

    #print status
    print "Scan still running"

    #kill old connections
    c.close()
    time.sleep(10)


#scanning done
print "Scanning done"

#generate ad-hoc report

con = httplib.HTTPSConnection(nexposeip, 3780)
xml_request="""<ReportAdhocGenerateRequest session-id="%s"><AdhocReportConfig template-id="audit-report" format="pdf"><Filters><filter type="scan" id="%s"></filter></Filters></AdhocReportConfig></ReportAdhocGenerateRequest>""" % (session_id, scan_id)
headers={"Content-type":"text-xml"}

print "Requesting an adhoc report"

try:
    con.request("POST", "/api/1.2/xml", xml_request, headers)
    response=con.getresponse()
except:
    print "Results from the ReportAdhocGenerateRequest returned unexpected result"
    exit(-1)

if (vervar=='on'):
    print "Response status: %s, Response reason: %s" % (response.status, response.reason)
data = response.read()
if (vervar=="on"):
    print 'Data recieved %s' % data

#take the data received and look for what we need
#need to cut out the base64 content
base64_identifier="--AxB9sl3299asdjvbA"

content_start= "Content-Transfer-Encoding: base64"

start_of_base64 = data.rfind(content_start)

#print start_of_base64

end_of_base64=data.rfind(base64_identifier)
#print end_of_base64

base64_data = data[start_of_base64+len(content_start)+2:end_of_base64]
#print  base64_data

#decode the data to write
decoded= base64.b64decode(base64_data)

print "Saving the report"

#prepare to wrhite the file
if(outputvar != None):
    try:
        f = open(outputvar, "w")
        f.write(decoded)
    except:
        print "Could not write the file"
        exit(-1)