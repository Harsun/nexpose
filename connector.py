from pip._vendor import requests

__author__ = 'gokhan.karakas'

from xml.dom.minidom import parseString, parse
import socket, urllib2, httplib
import ssl


class config(object):

    #Connection Settings
    dom = parse("config.xml")
    hostname = dom.getElementsByTagName("host")[0].firstChild.nodeValue
    port = dom.getElementsByTagName("port")[0].firstChild.nodeValue
    username = dom.getElementsByTagName("user_name")[0].firstChild.nodeValue
    password = dom.getElementsByTagName("user_pass")[0].firstChild.nodeValue
    url = dom.getElementsByTagName("url")[0].firstChild.nodeValue


    #Nexpose Settings
    session_id=""
    site_id=""
    scan_id=""

    ctx = ssl.create_default_context()
    ctx.check_hostname=False
    ctx.verify_mode=ssl.CERT_NONE

    headers = {"Content-type":"text/xml"}

    #Login call to Nexpose
    def login():
        url = "https://" + hostname +":" + port + url

        xml_request = """<LoginRequest user-id="%s" password="%s" />""" % (username, password)
        connect = urllib2.Request(url,xml_request,headers)
        response = urllib2.urlopen(connect,context=ctx).read()
        print response
        result = parseString(response)
        try:
            xmlTag = result.getElementsByTagName("LoginResponse")[0]
            successvalue = xmlTag.getAttribute("success")
            session_id = xmlTag.getAttribute("session-id")
            return (session_id, successvalue)
        except:
            print "Login response exception occured"
            return exit(-1)
    session_id , successvalue = login()
    def logout():
        xml_request = """<LogoutRequest session-id="%s" />""" % session_id
        connect = urllib2.Request(url, xml_request, headers)


