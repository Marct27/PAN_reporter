#!/usr/bin/python
# Palo Alto Networks Simple Python reporting script
# by Marc Thompson - Layer 7

# This script will run aginst the firewall entered in the variable below
# The process is as follows:
# * Pull a list of reports from config file
# * Call API and capture the Job ID's associated with each report
# * Check Job ID status and fetch report from firewall

import urllib2
import ssl
import xml.etree.ElementTree as ET
import json
import time
import os

# Workaround for self signed cerificates
ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
rootdir = os.getcwd()

# Force document formating as XML
head = 'headers={"Accept" : "application/xml"}'


def parseXML(arg1, arg2):
    # Parse xml and get root key value
    tree = ET.parse(resp)
    root = tree.getroot()
    # From return xml find job id of report
    j = root.find(arg1)
    jID = j.find(arg2)
    print('Job ID :', jID.text)
    return jID


def urlRequest(arg1):
    # Request url and open
    req = urllib2.Request(host+arg1, head)
    resp = urllib2.urlopen(req, context=ctx)
    return resp


for config in os.listdir(rootdir):  # Read configs from directory
    if config.endswith(".conf"):
        with open(config) as json_data_file:
            cfg = json.load(json_data_file)

        # Check for existing path and create if not found
        path = os.path.join(os.getcwd(), cfg['customer'], cfg['interval'])
        if not os.path.exists(path):
            os.makedirs(path)

        # Define local variables from config file
        host = 'https://'+cfg['fw']['host']
        apiKey = cfg['fw']['apiKey']
        reports = cfg['fw']['reports']['reportName']
        vsys = cfg['fw']['vsys']

        # Loop through reports
        for i in reports:
            # Verify if a vsys is required
            if vsys == "":
                apiRunReport = '/api/?type=report&async=yes&reporttype=\
                custom&reportname=%s&key=%s' % (i, apiKey)
            else:
                apiRunReport = '/api/?type=report&async=yes&reporttype=\
                custom&vsys=%s&reportname=%s&key=%s' % (vsys, i, apiKey)

            print('API URL Called for', i, ':', apiRunReport)

            # Call URL and parse XML
            resp = urlRequest(apiRunReport)
            jID = parseXML('result', 'job')

            # Check status of jobs to ensure job has run before pulling report
            state = ""
            while state != 'FIN':
                time.sleep(5)
            # From xml get job status
                apiPullReport = '/api/?type=report&action=get&job-id=%s\
                &key=%s' % (jID.text, apiKey)
                resp = urlRequest(apiPullReport)
                tree = ET.parse(resp)
                root = tree.getroot()
                for s in root.iter('status'):
                    print(
                        "Job# {} for report : {} - Status: {}".format
                        (jID.text, i, s.text))
                    state = s.text
                # Pull report
                rep = urllib2.urlopen(host+apiPullReport, context=ctx,)\
                    .read()
                # Write report to file
                reportdir = os.path.join(path, '{}.xml'.format(i))
                file = open(reportdir, 'w')
                file.write(rep)
                file.close()
print("FINISHED !!")
