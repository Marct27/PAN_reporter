#!/usr/bin/python

# Palo Alto Networks Simple Python reporting script
# by Marc Thompson - Layer 7

# This script will run aginst the firewall entered in the variable below

# The process is as follows:
# * Pull a list of reports from config file
# * Call API and capture the Job ID's associated with each report
# * Check Job ID status and fetch report from firewall

import urllib.request
import urllib.error
import urllib.parse
import ssl
import xml.etree.ElementTree as ET
import json
import time
import os
import glob

# Workaround for self signed cerificates
ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
rootdir = os.getcwd()


def parseXML(arg1, arg2, arg3):
    req = urllib.request.Request(
                                host+arg3, data=None,
                                headers={"Accept": "application/xml"})
    resp = urllib.request.urlopen(req, context=ctx)
# Parse xml and get root key value
    tree = ET.parse(resp)
    root = tree.getroot()
    # From return xml find job id of report
    j = root.find(arg1)
    return j.find(arg2)



def urlRequest(arg1):
    # Request url and open
    req = urllib.request.Request(
                                host+arg1, data=None,
                                headers={"Accept": "application/xml"})
    return urllib.request.urlopen(req, context=ctx)

for config in glob.glob("*.conf"):  # Read configs from directory
    # if config.endswith(".conf"):
    with open(config) as json_data_file:
        cfg = json.load(json_data_file)

    # Define local variables from config file
    path = os.path.join(cfg['save_folder'], cfg['customer_folder'], cfg['report_folder'])
    host = 'https://'+cfg['fw']['host']
    apiKey = cfg['fw']['apiKey']
    reports = cfg['fw']['reports']['reportName']
    vsys = cfg['fw']['vsys']
    custom = cfg['fw']['custom_reports']['required']
    custom_reports = cfg['fw']['custom_reports']['reports']
    operational = cfg['fw']['operational_reports']['required']
    operational_reports = cfg['fw']['operational_reports']['reports']
    rname = {}

    if not os.path.exists(path):
        os.makedirs(path)

    print('Generating Report Jobs for {}'.format(config))

    # Loop through reports
    for i in reports:
        if vsys == "": # Verify if a vsys is required
            apiRunReport = '/api/?type=report&async=yes&reporttype=custom&reportname=%s&key=%s' % (i, apiKey)
        else:
            apiRunReport = '/api/?type=report&async=yes&reporttype=custom&vsys=%s&reportname=%s&key=%s' % (vsys, i, apiKey)
        jID = parseXML('result', 'job', apiRunReport)
        rname[i] = jID.text

    if custom == "yes":
        for i, v in custom_reports.items():
            uri = urllib.parse.quote(v,safe='/', encoding='utf-8', errors=None)
            customRunReport = '/api/?type=report&async=yes&reporttype=dynamic&reportname=custom-dynamic-report&cmd=%s&key=%s' % (uri, apiKey)
            jID = parseXML('result', 'job', customRunReport)
            rname[i] = jID.text
            #print(customRunReport)

    if operational == "yes":
        for i, v in operational_reports.items():
            print('Writing operations report - {}'.format(i))
            operationRunReport = '%s&key=%s' % (v, apiKey)
            resp = urlRequest(operationRunReport)
            tree = ET.parse(resp)
            fpath = os.path.basename(os.getcwd())
            reportdir = os.path.join(path, '{}-{}.xml'.format(i, fpath))
            tree.write(reportdir)


    for i, v in rname.items():
        state = ""
        while state != 'FIN':
        # From xml get job status
            apiPullReport = '/api/?type=report&action=get&job-id=%s&key=%s' % (v, apiKey)
            # print(apiPullReport)
            resp = urlRequest(apiPullReport)
            tree = ET.parse(resp)
            root = tree.getroot()
            for s in root.iter('status'):
                state = s.text
            if state != 'FIN':
                print('Job status: {} retry in 5 sec'.format(s.text))
                time.sleep(5)
            else:
                # Write report to file
                print(
                    "Writing to file: Job# {} for report : {} - Status: {}".format
                    (jID.text, i, s.text))
                fpath = os.path.basename(os.getcwd())
                reportdir = os.path.join(path, '{}-{}.xml'.format(i, fpath))
                tree.write(reportdir)

print("FINISHED !!")
