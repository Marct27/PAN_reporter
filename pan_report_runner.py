#!/usr/bin/python
# Palo Alto Networks Simple Python reporting script
# by Marc Thompson - Layer 7

# This script will run aginst the firewall entered in the variable below
# The process is as follows:
# * Pull a list of reports from config file(s)
# * Call API and capture the Job ID's associated with each report
# * Check Job ID status and fetch report from firewall

import urllib2
import ssl
import xml.etree.ElementTree as ET
import json
import time
import os

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
rootdir = os.getcwd()
head = 'headers={"Accept" : "application/xml"}'


for config in os.listdir(rootdir):
    if config.endswith(".conf"):
        with open(config) as json_data_file:
            cfg = json.load(json_data_file)

        path = os.path.join(os.getcwd(),cfg['customer'],cfg['interval'])
        if not os.path.exists(path):
            os.makedirs(path)

        host = 'https://'+cfg['fw']['host']
        apiKey = cfg['fw']['apiKey']
        reports = cfg['fw']['reports']['reportName']
        vsys = cfg['fw']['vsys']
        for i in reports:
            #build URL to get reports from report name list
            #Verify if a vsys is required
            if vsys == "":
                apiRunReport = '/api/?type=report&async=yes&reporttype=custom&reportname=%s&key=%s' % (i, apiKey)
            else:
                apiRunReport = '/api/?type=report&async=yes&reporttype=custom&vsys=%s&reportname=%s&key=%s' % (vsys, i, apiKey)
            print 'API URL Called for', i, ':', apiRunReport

    #        #Request url and open
            req = urllib2.Request(host+apiRunReport, head)
            resp = urllib2.urlopen(req, context = ctx)

            #Parse xml and get root key value
            tree = ET.parse(resp)
            root = tree.getroot()

            #From return xml find job id of report
            j=root.find('result')
            jID=j.find('job')
            print 'Job ID :', jID.text

            state = ""
            while state != 'FIN':
                time.sleep(5)
            #From xml get job status
                apiPullReport = '/api/?type=report&action=get&job-id=%s&key=%s' % (jID.text, apiKey)
                req = urllib2.Request(host+apiPullReport, head)
                resp = urllib2.urlopen(req, context = ctx)
                tree = ET.parse(resp)
                root = tree.getroot()
                jobState=root.find('result')
                status=jobState.find('job') 
                for s in root.iter('status'):
                    print 'Job# {} for report : {} - Status: {}'.format(jID.text, i, s.text)
                    state = s.text
                rep = urllib2.urlopen(host+apiPullReport, context = ctx,).read()
                reportdir = os.path.join(path, '{}.xml'.format(i))
                file = open(reportdir, 'w')
                file.write(rep)
                file.close()
print "FINISHED !!"                

