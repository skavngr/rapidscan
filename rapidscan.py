#!/usr/bin/python
# -*- coding: utf-8 -*-
#                               __         __
#                              /__)_   '_/(  _ _
#                             / ( (//)/(/__)( (//)
#                                  /
#
# Author	 : Shankar Damodaran
# Tool 		 : RapidScan
# Usage		 : ./rapidscan.py example.com (or) python rapidsan.py example.com
# Description: This scanner automates the process of security scanning by using a
#              multitude of available linux security tools and some custom scripts.
#

# Importing the libraries
import sys
import socket
import subprocess
import os
import time
import signal
import random
import string
import threading
import re
from urlparse import urlsplit



# Scan Time Elapser
intervals = (
    ('h', 3600),
    ('m', 60),
    ('s', 1),
    )
def display_time(seconds, granularity=3):
    result = []
    seconds = seconds + 1
    for name, count in intervals:
        value = seconds // count
        if value:
            seconds -= value * count
            result.append("{}{}".format(value, name))
    return ' '.join(result[:granularity])


def url_maker(url):
	if not re.match(r'http(s?)\:', url):
		url = 'http://' + url
	parsed = urlsplit(url)
	host = parsed.netloc
	if host.startswith('www.'):
		host = host[4:]
	return host

def check_internet():
    os.system('ping -c1 github.com > rs_net 2>&1')
    if "0% packet loss" in open('rs_net').read():
        val = 1
    else:
        val = 0
    os.system('rm rs_net > /dev/null 2>&1')
    return val


# Initializing the color module class
class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    BADFAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

    BG_ERR_TXT 	= '\033[41m' # For critical errors and crashes
    BG_HEAD_TXT = '\033[100m'
    BG_ENDL_TXT = '\033[46m'
    BG_CRIT_TXT = '\033[45m'
    BG_HIGH_TXT = '\033[41m'
    BG_MED_TXT  = '\033[43m'
    BG_LOW_TXT  = '\033[44m'
    BG_INFO_TXT = '\033[42m'


# Classifies the Vulnerability's Severity
def vul_info(val):
	result =''
	if val == 'c':
		result = bcolors.BG_CRIT_TXT+" critical "+bcolors.ENDC
	elif val == 'h':
		result = bcolors.BG_HIGH_TXT+" high "+bcolors.ENDC
	elif val == 'm':
		result = bcolors.BG_MED_TXT+" medium "+bcolors.ENDC
	elif val == 'l':
		result = bcolors.BG_LOW_TXT+" low "+bcolors.ENDC
	else:
		result = bcolors.BG_INFO_TXT+" info "+bcolors.ENDC
	return result

# Legends
proc_high = bcolors.BADFAIL + "●" + bcolors.ENDC
proc_med  = bcolors.WARNING + "●" + bcolors.ENDC
proc_low  = bcolors.OKGREEN + "●" + bcolors.ENDC

# Links the vulnerability with threat level and remediation database
def vul_remed_info(v1,v2,v3):
	print bcolors.BOLD+"Vulnerability Threat Level"+bcolors.ENDC
	print "\t"+vul_info(v2)+" "+bcolors.WARNING+str(tool_resp[v1][0])+bcolors.ENDC
	print bcolors.BOLD+"Vulnerability Definition"+bcolors.ENDC
	print "\t"+bcolors.BADFAIL+str(tools_fix[v3-1][1])+bcolors.ENDC
	print bcolors.BOLD+"Vulnerability Remediation"+bcolors.ENDC
	print "\t"+bcolors.OKGREEN+str(tools_fix[v3-1][2])+bcolors.ENDC


# RapidScan Help Context
def helper():
        print bcolors.OKBLUE+"Information:"+bcolors.ENDC
        print "------------"
        print "\t./rapidscan.py example.com: Scans the domain example.com"
        print "\t./rapidscan.py --update   : Updates the scanner to the latest version."
        print "\t./rapidscan.py --help     : Displays this help context."
        print bcolors.OKBLUE+"Interactive:"+bcolors.ENDC
        print "------------"
        print "\tCtrl+C: Skips current test."
        print "\tCtrl+Z: Quits RapidScan."
        print bcolors.OKBLUE+"Legends:"+bcolors.ENDC
        print "--------"
        print "\t["+proc_high+"]: Scan process may take longer times (not predictable)."
        print "\t["+proc_med+"]: Scan process may take less than 10 minutes."
        print "\t["+proc_low+"]: Scan process may take less than a minute or two."
        print bcolors.OKBLUE+"Vulnerability Information:"+bcolors.ENDC
        print "--------------------------"
        print "\t"+vul_info('c')+": Requires immediate attention as it may lead to compromise or service unavailability."
        print "\t"+vul_info('h')+"    : May not lead to an immediate compromise, but there are high chances of probability."
        print "\t"+vul_info('m')+"  : Attacker may correlate multiple vulnerabilities of this type to launch a sophisticated attack."
        print "\t"+vul_info('l')+"     : Not a serious issue, but it is recommended to attend the finding."
        print "\t"+vul_info('i')+"    : Not classified as a vulnerability, simply an useful informational alert to be considered.\n"


# Clears Line
def clear():
        sys.stdout.write("\033[F")
        sys.stdout.write("\033[K")

# RapidScan Logo
def logo():
	print bcolors.WARNING
        print("""\
                                  __         __
                                 /__)_  """+bcolors.BADFAIL+" ●"+bcolors.WARNING+"""_/(  _ _
                                / ( (//)/(/__)( (//)
                                     /
                     """+bcolors.ENDC+"""(The Multi-Tool Web Vulnerability Scanner)
                            """)
        print bcolors.ENDC

# Initiliazing the idle loader/spinner class
class Spinner:
    busy = False
    delay = 0.05

    @staticmethod
    def spinning_cursor():
        while 1:
            for cursor in '|/\\': yield cursor #←↑↓→
            #for cursor in '←↑↓→': yield cursor
    def __init__(self, delay=None):
        self.spinner_generator = self.spinning_cursor()
        if delay and float(delay): self.delay = delay

    def spinner_task(self):
        try:
            while self.busy:
                #sys.stdout.write(next(self.spinner_generator))
                print bcolors.BG_ERR_TXT+next(self.spinner_generator)+bcolors.ENDC,
                sys.stdout.flush()
                time.sleep(self.delay)
                sys.stdout.write('\b')
                sys.stdout.flush()
        except (KeyboardInterrupt, SystemExit):
            #clear()
            print "\n\t"+ bcolors.BG_ERR_TXT+"RapidScan received a series of Ctrl+C hits. Quitting..." +bcolors.ENDC
            sys.exit(1)

    def start(self):
        self.busy = True
        threading.Thread(target=self.spinner_task).start()

    def stop(self):
        try:
            self.busy = False
            time.sleep(self.delay)
        except (KeyboardInterrupt, SystemExit):
            #clear()
            print "\n\t"+ bcolors.BG_ERR_TXT+"RapidScan received a series of Ctrl+C hits. Quitting..." +bcolors.ENDC
            sys.exit(1)
# End ofloader/spinner class

# Instantiating the spinner/loader class
spinner = Spinner()



# Scanners that will be used and filename rotation (default: enabled (1))
tool_names = [
                ["host","Host - Checks for existence of IPV6 address.","host",1],
                ["aspnet_config_err","ASP.Net Misconfiguration - Checks for ASP.Net Misconfiguration.","wget",1],
                ["wp_check","WordPress Checker - Checks for WordPress Installation.","wget",1],
                ["drp_check", "Drupal Checker - Checks for Drupal Installation.","wget",1],
                ["joom_check", "Joomla Checker - Checks for Joomla Installation.","wget",1],
                ["uniscan","Uniscan - Checks for robots.txt & sitemap.xml","uniscan",1],
                ["wafw00f","Wafw00f - Checks for Application Firewalls.","wafw00f",1],
                ["nmap","Nmap - Fast Scan [Only Few Port Checks]","nmap",1],
                ["theharvester","The Harvester - Scans for emails using Google's passive search.","theharvester",1],
                ["dnsrecon","DNSRecon - Attempts Multiple Zone Transfers on Nameservers.","dnsrecon",1],
                ["fierce","Fierce - Attempts Zone Transfer [No Brute Forcing]","fierce",1],
                ["dnswalk","DNSWalk - Attempts Zone Transfer.","dnswalk",1],
                ["whois","WHOis - Checks for Administrator's Contact Information.","whois",1],
                ["nmap_header","Nmap [XSS Filter Check] - Checks if XSS Protection Header is present.","nmap",1],
                ["nmap_sloris","Nmap [Slowloris DoS] - Checks for Slowloris Denial of Service Vulnerability.","nmap",1],
                ["sslyze_hbleed","SSLyze - Checks only for Heartbleed Vulnerability.","sslyze",1],
                ["nmap_hbleed","Nmap [Heartbleed] - Checks only for Heartbleed Vulnerability.","nmap",1],
                ["nmap_poodle","Nmap [POODLE] - Checks only for Poodle Vulnerability.","nmap",1],
                ["nmap_ccs","Nmap [OpenSSL CCS Injection] - Checks only for CCS Injection.","nmap",1],
                ["nmap_freak","Nmap [FREAK] - Checks only for FREAK Vulnerability.","nmap",1],
                ["nmap_logjam","Nmap [LOGJAM] - Checks for LOGJAM Vulnerability.","nmap",1],
                ["sslyze_ocsp","SSLyze - Checks for OCSP Stapling.","sslyze",1],
                ["sslyze_zlib","SSLyze - Checks for ZLib Deflate Compression.","sslyze",1],
                ["sslyze_reneg","SSLyze - Checks for Secure Renegotiation Support and Client Renegotiation.","sslyze",1],
                ["sslyze_resum","SSLyze - Checks for Session Resumption Support with [Session IDs/TLS Tickets].","sslyze",1],
                ["lbd","LBD - Checks for DNS/HTTP Load Balancers.","lbd",1],
                ["golismero_dns_malware","Golismero - Checks if the domain is spoofed or hijacked.","golismero",1],
                ["golismero_heartbleed","Golismero - Checks only for Heartbleed Vulnerability.","golismero",1],
                ["golismero_brute_url_predictables","Golismero - BruteForces for certain files on the Domain.","golismero",1],
                ["golismero_brute_directories","Golismero - BruteForces for certain directories on the Domain.","golismero",1],
                ["golismero_sqlmap","Golismero - SQLMap [Retrieves only the DB Banner]","golismero",1],
                ["dirb","DirB - Brutes the target for Open Directories.","dirb",1],
                ["xsser","XSSer - Checks for Cross-Site Scripting [XSS] Attacks.","xsser",1],
                ["golismero_ssl_scan","Golismero SSL Scans - Performs SSL related Scans.","golismero",1],
                ["golismero_zone_transfer","Golismero Zone Transfer - Attempts Zone Transfer.","golismero",1],
                ["golismero_nikto","Golismero Nikto Scans - Uses Nikto Plugin to detect vulnerabilities.","golismero",1],
                ["golismero_brute_subdomains","Golismero Subdomains Bruter - Brute Forces Subdomain Discovery.","golismero",1],
                ["dnsenum_zone_transfer","DNSEnum - Attempts Zone Transfer.","dnsenum",1],
                ["fierce_brute_subdomains","Fierce Subdomains Bruter - Brute Forces Subdomain Discovery.","fierce",1],
                ["dmitry_email","DMitry - Passively Harvests Emails from the Domain.","dmitry",1],
                ["dmitry_subdomains","DMitry - Passively Harvests Subdomains from the Domain.","dmitry",1],
                ["nmap_telnet","Nmap [TELNET] - Checks if TELNET service is running.","nmap",1],
                ["nmap_ftp","Nmap [FTP] - Checks if FTP service is running.","nmap",1],
                ["nmap_stuxnet","Nmap [STUXNET] - Checks if the host is affected by STUXNET Worm.","nmap",1],
                ["webdav","WebDAV - Checks if WEBDAV enabled on Home directory.","davtest",1],
                ["golismero_finger","Golismero - Does a fingerprint on the Domain.","golismero",1],
                ["uniscan_filebrute","Uniscan - Brutes for Filenames on the Domain.","uniscan",1],
                ["uniscan_dirbrute", "Uniscan - Brutes Directories on the Domain.","uniscan",1],
                ["uniscan_ministresser", "Uniscan - Stress Tests the Domain.","uniscan",1],
                ["uniscan_rfi","Uniscan - Checks for LFI, RFI and RCE.","uniscan",1],#50
                ["uniscan_xss","Uniscan - Checks for XSS, SQLi, BSQLi & Other Checks.","uniscan",1],
                ["nikto_xss","Nikto - Checks for Apache Expect XSS Header.","nikto",1],
                ["nikto_subrute","Nikto - Brutes Subdomains.","nikto",1],
                ["nikto_shellshock","Nikto - Checks for Shellshock Bug.","nikto",1],
                ["nikto_internalip","Nikto - Checks for Internal IP Leak.","nikto",1],
                ["nikto_putdel","Nikto - Checks for HTTP PUT DEL.","nikto",1],
                ["nikto_headers","Nikto - Checks the Domain Headers.","nikto",1],
                ["nikto_ms01070","Nikto - Checks for MS10-070 Vulnerability.","nikto",1],
                ["nikto_servermsgs","Nikto - Checks for Server Issues.","nikto",1],
                ["nikto_outdated","Nikto - Checks if Server is Outdated.","nikto",1],
                ["nikto_httpoptions","Nikto - Checks for HTTP Options on the Domain.","nikto",1],
                ["nikto_cgi","Nikto - Enumerates CGI Directories.","nikto",1],
                ["nikto_ssl","Nikto - Performs SSL Checks.","nikto",1],
                ["nikto_sitefiles","Nikto - Checks for any interesting files on the Domain.","nikto",1],
                ["nikto_paths","Nikto - Checks for Injectable Paths.","nikto",1],
                ["dnsmap_brute","DNSMap - Brutes Subdomains.","dnsmap",1],
                ["nmap_sqlserver","Nmap - Checks for MS-SQL Server DB","nmap",1],
                ["nmap_mysql", "Nmap - Checks for MySQL DB","nmap",1],
                ["nmap_oracle", "Nmap - Checks for ORACLE DB","nmap",1],
                ["nmap_rdp_udp","Nmap - Checks for Remote Desktop Service over UDP","nmap",1],
                ["nmap_rdp_tcp","Nmap - Checks for Remote Desktop Service over TCP","nmap",1],
                ["nmap_full_ps_tcp","Nmap - Performs a Full TCP Port Scan","nmap",1],
                ["nmap_full_ps_udp","Nmap - Performs a Full UDP Port Scan","nmap",1],
                ["nmap_snmp","Nmap - Checks for SNMP Service","nmap",1],
                ["aspnet_elmah_axd","Checks for ASP.net Elmah Logger","wget",1],
                ["nmap_tcp_smb","Checks for SMB Service over TCP","nmap",1],
                ["nmap_udp_smb","Checks for SMB Service over UDP","nmap",1],
                ["wapiti","Wapiti - Checks for SQLi, RCE, XSS and Other Vulnerabilities","wapiti",1],
                ["nmap_iis","Nmap - Checks for IIS WebDAV","nmap",1],
                ["whatweb","WhatWeb - Checks for X-XSS Protection Header","whatweb",1]
            ]


# Command that is used to initiate the tool (with parameters and extra params)
tool_cmd   = [
                ["host ",""],
                ["wget -O temp_aspnet_config_err --tries=1 ","/%7C~.aspx"],
                ["wget -O temp_wp_check --tries=1 ","/wp-admin"],
                ["wget -O temp_drp_check --tries=1 ","/user"],
                ["wget -O temp_joom_check --tries=1 ","/administrator"],
                ["uniscan -e -u ",""],
                ["wafw00f ",""],
                ["nmap -F --open -Pn ",""],
                ["theharvester -l 50 -b google -d ",""],
                ["dnsrecon -d ",""],
                ["fierce -wordlist xxx -dns ",""],
                ["dnswalk -d ","."],
                ["whois ",""],
                ["nmap -p80 --script http-security-headers -Pn ",""],
                ["nmap -p80,443 --script http-slowloris --max-parallelism 500 -Pn ",""],
                ["sslyze --heartbleed ",""],
                ["nmap -p443 --script ssl-heartbleed -Pn ",""],
                ["nmap -p443 --script ssl-poodle -Pn ",""],
                ["nmap -p443 --script ssl-ccs-injection -Pn ",""],
                ["nmap -p443 --script ssl-enum-ciphers -Pn ",""],
                ["nmap -p443 --script ssl-dh-params -Pn ",""],
                ["sslyze --certinfo=basic ",""],
                ["sslyze --compression ",""],
                ["sslyze --reneg ",""],
                ["sslyze --resum ",""],
                ["lbd ",""],
                ["golismero -e dns_malware scan ",""],
                ["golismero -e heartbleed scan ",""],
                ["golismero -e brute_url_predictables scan ",""],
                ["golismero -e brute_directories scan ",""],
                ["golismero -e sqlmap scan ",""],
                ["dirb http://"," -fi"],
                ["xsser --all=http://",""],
                ["golismero -e sslscan scan ",""],
                ["golismero -e zone_transfer scan ",""],
                ["golismero -e nikto scan ",""],
                ["golismero -e brute_dns scan ",""],
                ["dnsenum ",""],
                ["fierce -dns ",""],
                ["dmitry -e ",""],
                ["dmitry -s ",""],
                ["nmap -p23 --open -Pn ",""],
                ["nmap -p21 --open -Pn ",""],
                ["nmap --script stuxnet-detect -p445 -Pn ",""],
                ["davtest -url http://",""],
                ["golismero -e fingerprint_web scan ",""],
                ["uniscan -w -u ",""],
                ["uniscan -q -u ",""],
                ["uniscan -r -u ",""],
                ["uniscan -s -u ",""],
                ["uniscan -d -u ",""],
                ["nikto -Plugins 'apache_expect_xss' -host ",""],
                ["nikto -Plugins 'subdomain' -host ",""],
                ["nikto -Plugins 'shellshock' -host ",""],
                ["nikto -Plugins 'cookies' -host ",""],
                ["nikto -Plugins 'put_del_test' -host ",""],
                ["nikto -Plugins 'headers' -host ",""],
                ["nikto -Plugins 'ms10-070' -host ",""],
                ["nikto -Plugins 'msgs' -host ",""],
                ["nikto -Plugins 'outdated' -host ",""],
                ["nikto -Plugins 'httpoptions' -host ",""],
                ["nikto -Plugins 'cgi' -host ",""],
                ["nikto -Plugins 'ssl' -host ",""],
                ["nikto -Plugins 'sitefiles' -host ",""],
                ["nikto -Plugins 'paths' -host ",""],
                ["dnsmap ",""],
                ["nmap -p1433 --open -Pn ",""],
                ["nmap -p3306 --open -Pn ",""],
                ["nmap -p1521 --open -Pn ",""],
                ["nmap -p3389 --open -sU -Pn ",""],
                ["nmap -p3389 --open -sT -Pn ",""],
                ["nmap -p1-65535 --open -Pn ",""],
                ["nmap -p1-65535 -sU --open -Pn ",""],
                ["nmap -p161 -sU --open -Pn ",""],
                ["wget -O temp_aspnet_elmah_axd --tries=1 ","/elmah.axd"],
                ["nmap -p445,137-139 --open -Pn ",""],
                ["nmap -p137,138 --open -Pn ",""],
                ["wapiti "," -f txt -o temp_wapiti"],
                ["nmap -p80 --script=http-iis-webdav-vuln -Pn ",""],
                ["whatweb "," -a 1"]
            ]


# Tool Responses (Begins) [Responses + Severity (c - critical | h - high | m - medium | l - low | i - informational) + Reference for Vuln Definition and Remediation]
tool_resp   = [
                ["Does not have an IPv6 Address. It is good to have one.","i",1],
                ["ASP.Net is misconfigured to throw server stack errors on screen.","m",2],
                ["WordPress Installation Found. Check for vulnerabilities corresponds to that version.","i",3],
                ["Drupal Installation Found. Check for vulnerabilities corresponds to that version.","i",4],
                ["Joomla Installation Found. Check for vulnerabilities corresponds to that version.","i",5],
                ["robots.txt/sitemap.xml found. Check those files for any information.","i",6],
                ["No Web Application Firewall Detected","m",7],
                ["Some ports are open. Perform a full-scan manually.","l",8],
                ["Email Addresses Found.","l",9],
                ["Zone Transfer Successful using DNSRecon. Reconfigure DNS immediately.","h",10],
                ["Zone Transfer Successful using fierce. Reconfigure DNS immediately.","h",10],
                ["Zone Transfer Successful using dnswalk. Reconfigure DNS immediately.","h",10],
                ["Whois Information Publicly Available.","i",11],
                ["XSS Protection Filter is Disabled.","m",12],
                ["Vulnerable to Slowloris Denial of Service.","c",13],
                ["HEARTBLEED Vulnerability Found with SSLyze.","h",14],
                ["HEARTBLEED Vulnerability Found with Nmap.","h",14],
                ["POODLE Vulnerability Detected.","h",15],
                ["OpenSSL CCS Injection Detected.","h",16],
                ["FREAK Vulnerability Detected.","h",17],
                ["LOGJAM Vulnerability Detected.","h",18],
                ["Unsuccessful OCSP Response.","m",19],
                ["Server supports Deflate Compression.","m",20],
                ["Secure Renegotiation is unsupported.","m",21],
                ["Secure Resumption unsupported with (Sessions IDs/TLS Tickets).","m",22],
                ["No DNS/HTTP based Load Balancers Found.","l",23],
                ["Domain is spoofed/hijacked.","h",24],
                ["HEARTBLEED Vulnerability Found with Golismero.","h",14],
                ["Open Files Found with Golismero BruteForce.","m",25],
                ["Open Directories Found with Golismero BruteForce.","m",26],
                ["DB Banner retrieved with SQLMap.","l",27],
                ["Open Directories Found with DirB.","m",26],
                ["XSSer found XSS vulnerabilities.","c",28],
                ["Found SSL related vulnerabilities with Golismero.","m",29],
                ["Zone Transfer Successful with Golismero. Reconfigure DNS immediately.","h",10],
                ["Golismero Nikto Plugin found vulnerabilities.","m",30],
                ["Found Subdomains with Golismero.","m",31],
                ["Zone Transfer Successful using DNSEnum. Reconfigure DNS immediately.","h",10],
                ["Found Subdomains with Fierce.","m",31],
                ["Email Addresses discovered with DMitry.","l",9],
                ["Subdomains discovered with DMitry.","m",31],
                ["Telnet Service Detected.","h",32],
                ["FTP Service Detected.","c",33],
                ["Vulnerable to STUXNET.","c",34],
                ["WebDAV Enabled.","m",35],
                ["Found some information through Fingerprinting.","l",36],
                ["Open Files Found with Uniscan.","m",25],
                ["Open Directories Found with Uniscan.","m",26],
                ["Vulnerable to Stress Tests.","h",37],
                ["Uniscan detected possible LFI, RFI or RCE.","h",38],
                ["Uniscan detected possible XSS, SQLi, BSQLi.","h",39],
                ["Apache Expect XSS Header not present.","m",12],
                ["Found Subdomains with Nikto.","m",31],
                ["Webserver vulnerable to Shellshock Bug.","c",40],
                ["Webserver leaks Internal IP.","l",41],
                ["HTTP PUT DEL Methods Enabled.","m",42],
                ["Some vulnerable headers exposed.","m",43],
                ["Webserver vulnerable to MS10-070.","h",44],
                ["Some issues found on the Webserver.","m",30],
                ["Webserver is Outdated.","h",45],
                ["Some issues found with HTTP Options.","l",42],
                ["CGI Directories Enumerated.","l",26],
                ["Vulnerabilities reported in SSL Scans.","m",29],
                ["Interesting Files Detected.","m",25],
                ["Injectable Paths Detected.","l",46],
                ["Found Subdomains with DNSMap.","m",31],
                ["MS-SQL DB Service Detected.","l",47],
                ["MySQL DB Service Detected.","l",47],
                ["ORACLE DB Service Detected.","l",47],
                ["RDP Server Detected over UDP.","h",48],
                ["RDP Server Detected over TCP.","h",48],
                ["TCP Ports are Open","l",8],
                ["UDP Ports are Open","l",8],
                ["SNMP Service Detected.","m",49],
                ["Elmah is Configured.","m",50],
                ["SMB Ports are Open over TCP","m",51],
                ["SMB Ports are Open over UDP","m",51],
                ["Wapiti discovered a range of vulnerabilities","h",30],
                ["IIS WebDAV is Enabled","m",35],
                ["X-XSS Protection is not Present","m",12]



            ]

# Tool Responses (Ends)



# Tool Status (Response Data + Response Code (if status check fails and you still got to push it + Legends + Approx Time + Tool Identification + Bad Responses)
tool_status = [
                ["has IPv6",1,proc_low," < 15s","ipv6",["not found","has IPv6"]],
                ["Server Error",0,proc_low," < 30s","asp.netmisconf",["unable to resolve host address","Connection timed out"]],
                ["wp-login",0,proc_low," < 30s","wpcheck",["unable to resolve host address","Connection timed out"]],
                ["drupal",0,proc_low," < 30s","drupalcheck",["unable to resolve host address","Connection timed out"]],
                ["joomla",0,proc_low," < 30s","joomlacheck",["unable to resolve host address","Connection timed out"]],
                ["[+]",0,proc_low," < 40s","robotscheck",["Use of uninitialized value in unpack at"]],
                ["No WAF",0,proc_low," < 45s","wafcheck",["appears to be down"]],
                ["tcp open",0,proc_med," <  2m","nmapopen",["Failed to resolve"]],
                ["No emails found",1,proc_med," <  3m","harvester",["No hosts found","No emails found"]],
                ["[+] Zone Transfer was successful!!",0,proc_low," < 20s","dnsreconzt",["Could not resolve domain"]],
                ["Whoah, it worked",0,proc_low," < 30s","fiercezt",["none"]],
                ["0 errors",0,proc_low," < 35s","dnswalkzt",["!!!0 failures, 0 warnings, 3 errors."]],
                ["Admin Email:",0,proc_low," < 25s","whois",["No match for domain"]],
                ["XSS filter is disabled",0,proc_low," < 20s","nmapxssh",["Failed to resolve"]],
                ["VULNERABLE",0,proc_high," < 45m","nmapdos",["Failed to resolve"]],
                ["Server is vulnerable to Heartbleed",0,proc_low," < 40s","sslyzehb",["Could not resolve hostname"]],
                ["VULNERABLE",0,proc_low," < 30s","nmap1",["Failed to resolve"]],
                ["VULNERABLE",0,proc_low," < 35s","nmap2",["Failed to resolve"]],
                ["VULNERABLE",0,proc_low," < 35s","nmap3",["Failed to resolve"]],
                ["VULNERABLE",0,proc_low," < 30s","nmap4",["Failed to resolve"]],
                ["VULNERABLE",0,proc_low," < 35s","nmap5",["Failed to resolve"]],
                ["ERROR - OCSP response status is not successful",0,proc_low," < 25s","sslyze1",["Could not resolve hostname"]],
                ["VULNERABLE",0,proc_low," < 30s","sslyze2",["Could not resolve hostname"]],
                ["VULNERABLE",0,proc_low," < 25s","sslyze3",["Could not resolve hostname"]],
                ["VULNERABLE",0,proc_low," < 30s","sslyze4",["Could not resolve hostname"]],
                ["does NOT use Load-balancing",0,proc_med," <  4m","lbd",["NOT FOUND"]],
                ["No vulnerabilities found",1,proc_low," < 45s","golism1",["Cannot resolve domain name","No vulnerabilities found"]],
                ["No vulnerabilities found",1,proc_low," < 40s","golism2",["Cannot resolve domain name","No vulnerabilities found"]],
                ["No vulnerabilities found",1,proc_low," < 45s","golism3",["Cannot resolve domain name","No vulnerabilities found"]],
                ["No vulnerabilities found",1,proc_low," < 40s","golism4",["Cannot resolve domain name","No vulnerabilities found"]],
                ["No vulnerabilities found",1,proc_low," < 45s","golism5",["Cannot resolve domain name","No vulnerabilities found"]],
                ["FOUND: 0",1,proc_high," < 35m","dirb",["COULDNT RESOLVE HOST","FOUND: 0"]],
                ["Could not find any vulnerability!",1,proc_med," <  4m","xsser",["XSSer is not working propertly!","Could not find any vulnerability!"]],
                ["Occurrence ID",0,proc_low," < 45s","golism6",["Cannot resolve domain name"]],
                ["DNS zone transfer successful",0,proc_low," < 30s","golism7",["Cannot resolve domain name"]],
                ["Nikto found 0 vulnerabilities",1,proc_med," <  4m","golism8",["Cannot resolve domain name","Nikto found 0 vulnerabilities"]],
                ["Possible subdomain leak",0,proc_high," < 30m","golism9",["Cannot resolve domain name"]],
                ["AXFR record query failed:",1,proc_low," < 45s","dnsenumzt",["NS record query failed:","AXFR record query failed","no NS record for"]],
                ["Found 0 entries",1,proc_high," < 75m","fierce2",["Found 0 entries","is gimp"]],
                ["Found 0 E-Mail(s)",1,proc_low," < 30s","dmitry1",["Unable to locate Host IP addr","Found 0 E-Mail(s)"]],
                ["Found 0 possible subdomain(s)",1,proc_low," < 35s","dmitry2",["Unable to locate Host IP addr","Found 0 possible subdomain(s)"]],
                ["open",0,proc_low," < 15s","nmaptelnet",["Failed to resolve"]],
                ["open",0,proc_low," < 15s","nmapftp",["Failed to resolve"]],
                ["open",0,proc_low," < 20s","nmapstux",["Failed to resolve"]],
                ["SUCCEED",0,proc_low," < 30s","webdav",["is not DAV enabled or not accessible."]],
                ["No vulnerabilities found",1,proc_low," < 15s","golism10",["Cannot resolve domain name","No vulnerabilities found"]],
                ["[+]",0,proc_med," <  2m","uniscan2",["Use of uninitialized value in unpack at"]],
                ["[+]",0,proc_med," <  5m","uniscan3",["Use of uninitialized value in unpack at"]],
                ["[+]",0,proc_med," <  9m","uniscan4",["Use of uninitialized value in unpack at"]],
                ["[+]",0,proc_med," <  8m","uniscan5",["Use of uninitialized value in unpack at"]],
                ["[+]",0,proc_med," <  9m","uniscan6",["Use of uninitialized value in unpack at"]],
                ["0 item(s) reported",1,proc_low," < 35s","nikto1",["ERROR: Cannot resolve hostname","0 item(s) reported","No web server found","0 host(s) tested"]],
                ["0 item(s) reported",1,proc_low," < 35s","nikto2",["ERROR: Cannot resolve hostname","0 item(s) reported","No web server found","0 host(s) tested"]],
                ["0 item(s) reported",1,proc_low," < 35s","nikto3",["ERROR: Cannot resolve hostname","0 item(s) reported","No web server found","0 host(s) tested"]],
                ["0 item(s) reported",1,proc_low," < 35s","nikto4",["ERROR: Cannot resolve hostname","0 item(s) reported","No web server found","0 host(s) tested"]],
                ["0 item(s) reported",1,proc_low," < 35s","nikto5",["ERROR: Cannot resolve hostname","0 item(s) reported","No web server found","0 host(s) tested"]],
                ["0 item(s) reported",1,proc_low," < 35s","nikto6",["ERROR: Cannot resolve hostname","0 item(s) reported","No web server found","0 host(s) tested"]],
                ["0 item(s) reported",1,proc_low," < 35s","nikto7",["ERROR: Cannot resolve hostname","0 item(s) reported","No web server found","0 host(s) tested"]],
                ["0 item(s) reported",1,proc_low," < 35s","nikto8",["ERROR: Cannot resolve hostname","0 item(s) reported","No web server found","0 host(s) tested"]],
                ["0 item(s) reported",1,proc_low," < 35s","nikto9",["ERROR: Cannot resolve hostname","0 item(s) reported","No web server found","0 host(s) tested"]],
                ["0 item(s) reported",1,proc_low," < 35s","nikto10",["ERROR: Cannot resolve hostname","0 item(s) reported","No web server found","0 host(s) tested"]],
                ["0 item(s) reported",1,proc_low," < 35s","nikto11",["ERROR: Cannot resolve hostname","0 item(s) reported","No web server found","0 host(s) tested"]],
                ["0 item(s) reported",1,proc_low," < 35s","nikto12",["ERROR: Cannot resolve hostname","0 item(s) reported","No web server found","0 host(s) tested"]],
                ["0 item(s) reported",1,proc_low," < 35s","nikto13",["ERROR: Cannot resolve hostname","0 item(s) reported","No web server found","0 host(s) tested"]],
                ["0 item(s) reported",1,proc_low," < 35s","nikto14","ERROR: Cannot resolve hostname , 0 item(s) reported"],
                ["#1",0,proc_high," < 30m","dnsmap_brute",["[+] 0 (sub)domains and 0 IP address(es) found"]],
                ["open",0,proc_low," < 15s","nmapmssql",["Failed to resolve"]],
                ["open",0,proc_low," < 15s","nmapmysql",["Failed to resolve"]],
                ["open",0,proc_low," < 15s","nmaporacle",["Failed to resolve"]],
                ["open",0,proc_low," < 15s","nmapudprdp",["Failed to resolve"]],
                ["open",0,proc_low," < 15s","nmaptcprdp",["Failed to resolve"]],
                ["open",0,proc_high," > 50m","nmapfulltcp",["Failed to resolve"]],
                ["open",0,proc_high," > 75m","nmapfulludp",["Failed to resolve"]],
                ["open",0,proc_low," < 30s","nmapsnmp",["Failed to resolve"]],
                ["Microsoft SQL Server Error Log",0,proc_low," < 30s","elmahxd",["unable to resolve host address","Connection timed out"]],
                ["open",0,proc_low," < 20s","nmaptcpsmb",["Failed to resolve"]],
                ["open",0,proc_low," < 20s","nmapudpsmb",["Failed to resolve"]],
                ["Host:",0,proc_med," < 5m","wapiti",["none"]],
                ["WebDAV is ENABLED",0,proc_low," < 40s","nmapwebdaviis",["Failed to resolve"]],
                ["X-XSS-Protection[1",1,proc_med," < 3m","whatweb",["Timed out","Socket error","X-XSS-Protection[1"]]



            ]

# Vulnerabilities and Remediation
tools_fix = [
					[1, "Not a vulnerability, just an informational alert. The host does not have IPv6 support. IPv6 provides more security as IPSec (responsible for CIA - Confidentiality, Integrity and Availablity) is incorporated into this model. So it is good to have IPv6 Support.",
							"It is recommended to implement IPv6. More information on how to implement IPv6 can be found from this resource. https://www.cisco.com/c/en/us/solutions/collateral/enterprise/cisco-on-cisco/IPv6-Implementation_CS.html"],
					[2, "Sensitive Information Leakage Detected. The ASP.Net application does not filter out illegal characters in the URL. The attacker injects a special character (%7C~.aspx) to make the application spit sensitive information about the server stack.",
							"It is recommended to filter out special charaters in the URL and set a custom error page on such situations instead of showing default error messages. This resource helps you in setting up a custom error page on a Microsoft .Net Application. https://docs.microsoft.com/en-us/aspnet/web-forms/overview/older-versions-getting-started/deploying-web-site-projects/displaying-a-custom-error-page-cs"],
					[3, "It is not bad to have a CMS in WordPress. There are chances that the version may contain vulnerabilities or any third party scripts associated with it may possess vulnerabilities",
							"It is recommended to conceal the version of WordPress. This resource contains more information on how to secure your WordPress Blog. https://codex.wordpress.org/Hardening_WordPress"],
					[4, "It is not bad to have a CMS in Drupal. There are chances that the version may contain vulnerabilities or any third party scripts associated with it may possess vulnerabilities",
							"It is recommended to conceal the version of Drupal. This resource contains more information on how to secure your Drupal Blog. https://www.drupal.org/docs/7/site-building-best-practices/ensure-that-your-site-is-secure"],
					[5, "It is not bad to have a CMS in Joomla. There are chances that the version may contain vulnerabilities or any third party scripts associated with it may possess vulnerabilities",
							"It is recommended to conceal the version of Joomla. This resource contains more information on how to secure your Joomla Blog. https://www.incapsula.com/blog/10-tips-to-improve-your-joomla-website-security.html"],
					[6, "Sometimes robots.txt or sitemap.xml may contain rules such that certain links that are not supposed to be accessed/indexed by crawlers and search engines. Search engines may skip those links but attackers will be able to access it directly.",
							"It is a good practice not to include sensitive links in the robots or sitemap files."],
					[7, "Without a Web Application Firewall, An attacker may try to inject various attack patterns either manually or using automated scanners. An automated scanner may send hordes of attack vectors and patterns to validate an attack, there are also chances for the application to get DoS`ed (Denial of Service)",
							"Web Application Firewalls offer great protection against common web attacks like XSS, SQLi, etc. They also provide an additional line of defense to your security infrastructure. This resource contains information on web application firewalls that could suit your application. https://www.gartner.com/reviews/market/web-application-firewall"],
					[8, "Open Ports give attackers a hint to exploit the services. Attackers try to retrieve banner information through the ports and understand what type of service the host is running",
							"It is recommended to close the ports of unused services and use a firewall to filter the ports wherever necessary. This resource may give more insights. https://security.stackexchange.com/a/145781/6137"],
					[9, "Chances are very less to compromise a target with email addresses. However, attackers use this as a supporting data to gather information around the target. An attacker may make use of the username on the email address and perform brute-force attacks on not just email servers, but also on other legitimate panels like SSH, CMS, etc with a password list as they have a legitimate name. This is however a shoot in the dark scenario, the attacker may or may not be successful depending on the level of interest",
							"Since the chances of exploitation is feeble there is no need to take action. Perfect remediation would be choosing different usernames for different services will be more thoughtful."],
					[10, "Zone Transfer reveals critical topological information about the target. The attacker will be able to query all records and will have more or less complete knowledge about your host.",
							"Good practice is to restrict the Zone Transfer by telling the Master which are the IPs of the slaves that can be given access for the query. This SANS resource  provides more information. https://www.sans.org/reading-room/whitepapers/dns/securing-dns-zone-transfer-868"],
					[11, "The email address of the administrator and other information (address, phone, etc) is available publicly. An attacker may use these information to leverage an attack. This may not be used to carry out a direct attack as this is not a vulnerability. However, an attacker makes use of these data to build information about the target.",
							"Some administrators intentionally would have made this information public, in this case it can be ignored. If not, it is recommended to mask the information. This resource provides information on this fix. http://www.name.com/blog/how-tos/tutorial-2/2013/06/protect-your-personal-information-with-whois-privacy/"],
					[12, "As the target is lacking this header, older browsers will be prone to Reflected XSS attacks.",
							"Modern browsers does not face any issues with this vulnerability (missing headers). However, older browsers are strongly recommended to be upgraded."],
					[13, "This attack works by opening multiple simultaneous connections to the web server and it keeps them alive as long as possible by continously sending partial HTTP requests, which never gets completed. They easily slip through IDS by sending partial requests.",
							"If you are using Apache Module, `mod_antiloris` would help. For other setup you can find more detailed remediation on this resource. https://www.acunetix.com/blog/articles/slow-http-dos-attacks-mitigate-apache-http-server/"],
					[14, "This vulnerability seriously leaks private information of your host. An attacker can keep the TLS connection alive and can retrieve a maximum of 64K of data per heartbeat.",
							"PFS (Perfect Forward Secrecy) can be implemented to make decryption difficult. Complete remediation and resource information is available here. http://heartbleed.com/"],
					[15, "By exploiting this vulnerability, an attacker will be able gain access to sensitive data in a n encrypted session such as session ids, cookies and with those data obtained, will be able to impersonate that particular user.",
							"This is a flaw in the SSL 3.0 Protocol. A better remediation would be to disable using the SSL 3.0 protocol. For more information, check this resource. https://www.us-cert.gov/ncas/alerts/TA14-290A"],
					[16, "This attacks takes place in the SSL Negotiation (Handshake) which makes the client unaware of the attack. By successfully altering the handshake, the attacker will be able to pry on all the information that is sent from the client to server and vice-versa",
							"Upgrading OpenSSL to latest versions will mitigate this issue. This resource gives more information about the vulnerability and the associated remediation. http://ccsinjection.lepidum.co.jp/"],
					[17, "With this vulnerability the attacker will be able to perform a MiTM attack and thus compromising the confidentiality factor.",
							"Upgrading OpenSSL to latest version will mitigate this issue. Versions prior to 1.1.0 is prone to this vulnerability. More information can be found in this resource. https://bobcares.com/blog/how-to-fix-sweet32-birthday-attacks-vulnerability-cve-2016-2183/"],
					[18, "With the LogJam attack, the attacker will be able to downgrade the TLS connection which allows the attacker to read and modify any data passed over the connection.",
							"Make sure any TLS libraries you use are up-to-date, that servers you maintain use 2048-bit or larger primes, and that clients you maintain reject Diffie-Hellman primes smaller than 1024-bit. More information can be found in this resource. https://weakdh.org/"],
					[19, "Allows remote attackers to cause a denial of service (crash), and possibly obtain sensitive information in applications that use OpenSSL, via a malformed ClientHello handshake message that triggers an out-of-bounds memory access.",
							" OpenSSL versions 0.9.8h through 0.9.8q and 1.0.0 through 1.0.0c are vulnerable. It is recommended to upgrade the OpenSSL version. More resource and information can be found here. https://www.openssl.org/news/secadv/20110208.txt"],
					[20, "Otherwise termed as BREACH atack, exploits the compression in the underlying HTTP protocol. An attacker will be able to obtain email addresses, session tokens, etc from the TLS encrypted web traffic.",
							"Turning off TLS compression does not mitigate this vulnerability. First step to mitigation is to disable Zlib compression followed by other measures mentioned in this resource. http://breachattack.com/"],
					[21, "Otherwise termed as Plain-Text Injection attack, which allows MiTM attackers to insert data into HTTPS sessions, and possibly other types of sessions protected by TLS or SSL, by sending an unauthenticated request that is processed retroactively by a server in a post-renegotiation context.",
							"Detailed steps of remediation can be found from these resources. https://securingtomorrow.mcafee.com/technical-how-to/tips-securing-ssl-renegotiation/ https://www.digicert.com/news/2011-06-03-ssl-renego/ "],
					[22, "This vulnerability allows attackers to steal existing TLS sessions from users.",
							"Better advice is to disable session resumption. To harden session resumption, follow this resource that has some considerable information. https://wiki.crashtest-security.com/display/KB/Harden+TLS+Session+Resumption"],
					[23, "This has nothing to do with security risks, however attackers may use this unavailability of load balancers as an advantage to leverage a denial of service attack on certain services or on the whole application itself.",
							"Load-Balancers are highly encouraged for any web application. They improve performance times as well as data availability on during times of server outage. To know more information on load balancers and setup, check this resource. https://www.digitalocean.com/community/tutorials/what-is-load-balancing"],
					[24, "An attacker can forwarded requests that comes to the legitimate URL or web application to a third party address or to the attacker's location that can serve malware and affect the end user's machine.",
							"It is highly recommended to deploy DNSSec on the host target. Full deployment of DNSSEC will ensure the end user is connecting to the actual web site or other service corresponding to a particular domain name. For more information, check this resource. https://www.cloudflare.com/dns/dnssec/how-dnssec-works/"],
					[25, "Attackers may find considerable amount of information from these files. There are even chances attackers may get access to critical information from these files.",
							"It is recommended to block or restrict access to these files unless necessary."],
					[26, "Attackers may find considerable amount of information from these directories. There are even chances attackers may get access to critical information from these directories.",
							"It is recommended to block or restrict access to these directories unless necessary."],
					[27, "May not be SQLi vulnerable. An attacker will be able to know that the host is using a backend for operation.",
							"Banner Grabbing should be restricted and access to the services from outside would should be made minimum."],
					[28, "An attacker will be able to steal cookies, deface web application or redirect to any third party address that can serve malware.",
							"Input validation and Output Sanitization can completely prevent Cross Site Scripting (XSS) attacks. XSS attacks can be mitigated in future by properly following a secure coding methodology. The following comprehensive resource provides detailed information on fixing this vulnerability. https://www.owasp.org/index.php/XSS_(Cross_Site_Scripting)_Prevention_Cheat_Sheet"],
					[29, "SSL related vulnerabilities breaks the confidentiality factor. An attacker may perform a MiTM attack, intrepret and eavesdrop the communication.",
							"Proper implementation and upgraded version of SSL and TLS libraries are very critical when it comes to blocking SSL related vulnerabilities."],
					[30, "Particular Scanner found multiple vulnerabilities that an attacker may try to exploit the target.",
							"Refer to RS-Vulnerability-Report to view the complete information of the vulnerability, once the scan gets completed."],
					[31, "Attackers may gather more information from subdomains relating to the parent domain. Attackers may even find other services from the subdomains and try to learn the architecture of the target. There are even chances for the attacker to find vulnerabilities as the attack surface gets larger with more subdomains discovered.",
							"It is sometimes wise to block sub domains like development, staging to the outside world, as it gives more information to the attacker about the tech stack. Complex naming practices also help in reducing the attack surface as attackers find hard to perform subdomain bruteforcing through dictionaries and wordlists."],
					[32, "Through this deprecated protocol, an attacker may be able to perform MiTM and other complicated attacks.",
							"It is highly recommended to stop using this service and it is far outdated. SSH can be used to replace TELNET. For more information, check this resource https://www.ssh.com/ssh/telnet"],
					[33, "This protocol does not support secure communication and there are likely high chances for the attacker to eavesdrop the communication. Also, many FTP programs have exploits available in the web such that an attacker can directly crash the application or either get a SHELL access to that target.",
							"Proper suggested fix is use an SSH protocol instead of FTP. It supports secure communication and chances for MiTM attacks are quite rare."],
					[34, "The StuxNet is level-3 worm that exposes critical information of the target organization. It was a cyber weapon that was designed to thwart the nuclear intelligence of Iran. Seriously wonder how it got here? Hope this isn't a false positive Nmap ;)",
							"It is highly recommended to perform a complete rootkit scan on the host. For more information refer to this resource. https://www.symantec.com/security_response/writeup.jsp?docid=2010-071400-3123-99&tabid=3"],
					[35, "WebDAV is supposed to contain multiple vulnerabilities. In some case, an attacker may hide a malicious DLL file in the WebDAV share however, and upon convincing the user to open a perfectly harmless and legitimate file, execute code under the context of that user",
							"It is recommended to disable WebDAV. Some critical resource regarding disbling WebDAV can be found on this URL. https://www.networkworld.com/article/2202909/network-security/-webdav-is-bad---says-security-researcher.html"],
					[36, "Attackers always do a fingerprint of any server before they launch an attack. Fingerprinting gives them information about the server type, content- they are serving, last modification times etc, this gives an attacker to learn more information about the target",
							"A good practice is to obfuscate the information to outside world. Doing so, the attackers will have tough time understanding the server's tech stack and therefore leverage an attack."],
					[37, "Attackers mostly try to render web applications or service useless by flooding the target, such that blocking access to legitimate users. This may affect the business of a company or organization as well as the reputation",
							"By ensuring proper load balancers in place, configuring rate limits and multiple connection restrictions, such attacks can be drastically mitigated."],
					[38, "Intruders will be able to remotely include shell files and will be able to access the core file system or they will be able to read all the files as well. There are even higher chances for the attacker to remote execute code on the file system.",
							"Secure code practices will mostly prevent LFI, RFI and RCE attacks. The following resource gives a detailed insight on secure coding practices. https://wiki.sei.cmu.edu/confluence/display/seccode/Top+10+Secure+Coding+Practices"],
					[39, "Hackers will be able to steal data from the backend and also they can authenticate themselves to the website and can impersonate as any user since they have total control over the backend. They can even wipe out the entire database. Attackers can also steal cookie information of an authenticated user and they can even redirect the target to any malicious address or totally deface the application.",
							"Proper input validation has to be done prior to directly querying the database information. A developer should remember not to trust an end-user's input. By following a secure coding methodology attacks like SQLi, XSS and BSQLi. The following resource guides on how to implement secure coding methodology on application development. https://wiki.sei.cmu.edu/confluence/display/seccode/Top+10+Secure+Coding+Practices"],
					[40, "Attackers exploit the vulnerability in BASH to perform remote code execution on the target. An experienced attacker can easily take over the target system and access the internal sources of the machine",
							"This vulnerability can be mitigated by patching the version of BASH. The following resource gives an indepth analysis of the vulnerability and how to mitigate it. https://www.symantec.com/connect/blogs/shellshock-all-you-need-know-about-bash-bug-vulnerability https://www.digitalocean.com/community/tutorials/how-to-protect-your-server-against-the-shellshock-bash-vulnerability"],
					[41, "Gives attacker an idea on how the address scheming is done internally on the organizational network. Discovering the private addresses used within an organization can help attackers in carrying out network-layer attacks aiming to penetrate the organization's internal infrastructure.",
							"Restrict the banner information to the outside world from the disclosing service. More information on mitigating this vulnerability can be found here. https://portswigger.net/kb/issues/00600300_private-ip-addresses-disclosed"],
					[42, "There are chances for an attacker to manipulate files on the webserver.",
							"It is recommended to disable the HTTP PUT and DEL methods incase if you don't use any REST API Services. Following resources helps you how to disable these methods. http://www.techstacks.com/howto/disable-http-methods-in-tomcat.html https://docs.oracle.com/cd/E19857-01/820-5627/gghwc/index.html https://developer.ibm.com/answers/questions/321629/how-to-disable-http-methods-head-put-delete-option/"],
					[43, "Attackers try to learn more about the target from the amount of information exposed in the headers. An attacker may know what type of tech stack a web application is emphasizing and many other information.",
							"Banner Grabbing should be restricted and access to the services from outside would should be made minimum."],
					[44, "An attacker who successfully exploited this vulnerability could read data, such as the view state, which was encrypted by the server. This vulnerability can also be used for data tampering, which, if successfully exploited, could be used to decrypt and tamper with the data encrypted by the server.",
							"Microsoft has released a set of patches on their website to mitigate this issue. The information required to fix this vulnerability can be inferred from this resource. https://docs.microsoft.com/en-us/security-updates/securitybulletins/2010/ms10-070"],
					[45, "Any outdated web server may contain multiple vulnerabilities as their support would've been ended. An attacker may make use of such an opportunity to leverage attacks.",
							"It is highly recommended to upgrade the web server to the available latest version."],
					[46, "Hackers will be able to manipulate the URLs easily through a GET/POST request. They will be able to inject multiple attack vectors in the URL with ease and able to monitor the response as well",
							"By ensuring proper sanitization techniques and employing secure coding practices it will be impossible for the attacker to penetrate through. The following resource gives a detailed insight on secure coding practices. https://wiki.sei.cmu.edu/confluence/display/seccode/Top+10+Secure+Coding+Practices"],
					[47, "Since the attacker has knowledge about the particular type of backend the target is running, they will be able to launch a targetted exploit for the particular version. They may also try to authenticate with default credentials to get themselves through.",
							"Timely security patches for the backend has to be installed. Default credentials has to be changed. If possible, the banner information can be changed to mislead the attacker. The following resource gives more information on how to secure your backend. http://kb.bodhost.com/secure-database-server/"],
					[48, "Attackers may launch remote exploits to either crash the service or tools like ncrack to try brute-forcing the password on the target.",
							"It is recommended to block the service to outside world and made the service accessible only through the a set of allowed IPs only really neccessary. The following resource provides insights on the risks and as well as the steps to block the service. https://www.perspectiverisk.com/remote-desktop-service-vulnerabilities/"],
					[49, "Hackers will be able to read community strings through the service and enumerate quite an information from the target. Also, there are multiple Remote Code Execution and Denial of Service vulnerabilities related to SNMP services.",
							"Use a firewall to block the ports from the outside world. The following article gives wide insight on locking down SNMP service. https://www.techrepublic.com/article/lock-it-down-dont-allow-snmp-to-compromise-network-security/"],
					[50, "Attackers will be able to find the logs and error information generated by the application. They will also be able to see the status codes that was generated on the application. By combining all these information, the attacker will be able to leverage an attack.",
							"By restricting access to the logger application from the outside world will be more than enough to mitigate this weakness."],
					[51, "Cyber Criminals mainly target this service as it is very easier for them to perform a remote attack by running exploits. WannaCry Ransomware is one such example.",
							"Exposing SMB Service to the outside world is a bad idea, it is recommended to install latest patches for the service in order not to get compromised. The following resource provides a detailed information on SMB Hardening concepts. https://kb.iweb.com/hc/en-us/articles/115000274491-Securing-Windows-SMB-and-NetBios-NetBT-Services"]
			]

#vul_remed_info('c',50)
#sys.exit(1)

# Tool Set
tools_precheck = [
					["wapiti"], ["whatweb"], ["nmap"], ["golismero"], ["host"], ["wget"], ["uniscan"], ["wafw00f"], ["dirb"], ["davtest"], ["theharvester"], ["xsser"], ["dnsrecon"],["fierce"], ["dnswalk"], ["whois"], ["sslyze"], ["lbd"], ["golismero"], ["dnsenum"],["dmitry"], ["davtest"], ["nikto"], ["dnsmap"]
			     ]

# Shuffling Scan Order (starts)
scan_shuffle = list(zip(tool_names, tool_cmd, tool_resp, tool_status))
random.shuffle(scan_shuffle)
tool_names, tool_cmd, tool_resp, tool_status = zip(*scan_shuffle)
tool_checks = (len(tool_names) + len(tool_resp) + len(tool_status)) / 3 # Cross verification incase, breaks.
# Shuffling Scan Order (ends)

# Tool Head Pointer: (can be increased but certain tools will be skipped)
tool = 0

# Run Test
runTest = 1

# For accessing list/dictionary elements
arg1 = 0
arg2 = 1
arg3 = 2
arg4 = 3
arg5 = 4
arg6 = 5

# Detected Vulnerabilities [will be dynamically populated]
rs_vul_list = list()
rs_vul_num = 0
rs_vul = 0

# Total Time Elapsed
rs_total_elapsed = 0

# Tool Pre Checker
rs_avail_tools = 0

# Checks Skipped
rs_skipped_checks = 0


if len(sys.argv) == 1 :
    logo()
    helper()
else:
    target = sys.argv[1].lower()


    if target == '--update' or target == '-u' or target == '--u':
    	logo()
        print "RapidScan is updating....Please wait.\n"
        spinner.start()
        # Checking internet connectivity first...
        rs_internet_availability = check_internet()
        if rs_internet_availability == 0:
            print "\t"+ bcolors.BG_ERR_TXT + "There seems to be some problem connecting to the internet. Please try again or later." +bcolors.ENDC
            spinner.stop()
            sys.exit(1)
        cmd = 'sha1sum rapidscan.py | grep .... | cut -c 1-40'
        oldversion_hash = subprocess.check_output(cmd, shell=True)
        oldversion_hash = oldversion_hash.strip()
        os.system('wget -N https://raw.githubusercontent.com/skavngr/rapidscan/master/rapidscan.py -O rapidscan.py > /dev/null 2>&1')
        newversion_hash = subprocess.check_output(cmd, shell=True)
        newversion_hash = newversion_hash.strip()
        if oldversion_hash == newversion_hash :
            clear()
            print "\t"+ bcolors.OKBLUE +"You already have the latest version of RapidScan." + bcolors.ENDC
        else:
            clear()
            print "\t"+ bcolors.OKGREEN +"RapidScan successfully updated to the latest version." +bcolors.ENDC
        spinner.stop()
        sys.exit(1)

    elif target == '--help' or target == '-h' or target == '--h':
    	logo()
        helper()
        sys.exit(1)
    else:

        target = url_maker(target)
        os.system('rm te* > /dev/null 2>&1') # Clearing previous scan files
        os.system('clear')
        os.system('setterm -cursor off')
        logo()
        print bcolors.BG_HEAD_TXT+"[ Checking Available Security Scanning Tools Phase... Initiated. ]"+bcolors.ENDC
        unavail_tools = 0
        unavail_tools_names = list()
        while (rs_avail_tools < len(tools_precheck)):
			precmd = str(tools_precheck[rs_avail_tools][arg1])
			try:
				p = subprocess.Popen([precmd], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,shell=True)
				output, err = p.communicate()
				val = output + err
			except:
				print "\t"+bcolors.BG_ERR_TXT+"RapidScan was terminated abruptly..."+bcolors.ENDC
				sys.exit(1)
			if "not found" in val:
				print "\t"+bcolors.OKBLUE+tools_precheck[rs_avail_tools][arg1]+bcolors.ENDC+bcolors.BADFAIL+"...unavailable."+bcolors.ENDC
				for scanner_index, scanner_val in enumerate(tool_names):
					if scanner_val[2] == tools_precheck[rs_avail_tools][arg1]:
						scanner_val[3] = 0 # disabling scanner as it's not available.
						unavail_tools_names.append(tools_precheck[rs_avail_tools][arg1])
						unavail_tools = unavail_tools + 1
			else:
				print "\t"+bcolors.OKBLUE+tools_precheck[rs_avail_tools][arg1]+bcolors.ENDC+bcolors.OKGREEN+"...available."+bcolors.ENDC
			rs_avail_tools = rs_avail_tools + 1
			clear()
        unavail_tools_names = list(set(unavail_tools_names))
        if unavail_tools == 0:
        	print "\t"+bcolors.OKGREEN+"All Scanning Tools are available. All vulnerability checks will be performed by RapidScan."+bcolors.ENDC
        else:
        	print "\t"+bcolors.WARNING+"Some of these tools "+bcolors.BADFAIL+str(unavail_tools_names)+bcolors.ENDC+bcolors.WARNING+" are unavailable. RapidScan can still perform tests by excluding these tools from the tests. Please install these tools to fully utilize the functionality of RapidScan."+bcolors.ENDC
        print bcolors.BG_ENDL_TXT+"[ Checking Available Security Scanning Tools Phase... Completed. ]"+bcolors.ENDC
        print "\n"
        print bcolors.BG_HEAD_TXT+"[ Preliminary Scan Phase Initiated... Loaded "+str(tool_checks)+" vulnerability checks.  ]"+bcolors.ENDC
        #while (tool < 1):
        while(tool < len(tool_names)):
            print "["+tool_status[tool][arg3]+tool_status[tool][arg4]+"] Deploying "+str(tool+1)+"/"+str(tool_checks)+" | "+bcolors.OKBLUE+tool_names[tool][arg2]+bcolors.ENDC,
            if tool_names[tool][arg4] == 0:
            	print bcolors.WARNING+"...Scanning Tool Unavailable. Auto-Skipping Test..."+bcolors.ENDC
		rs_skipped_checks = rs_skipped_checks + 1
            	tool = tool + 1
            	continue
            spinner.start()
            scan_start = time.time()
            temp_file = "temp_"+tool_names[tool][arg1]
            cmd = tool_cmd[tool][arg1]+target+tool_cmd[tool][arg2]+" > "+temp_file+" 2>&1"

            try:
                subprocess.check_output(cmd, shell=True)
            except KeyboardInterrupt:
                runTest = 0
            except:
                runTest = 1

            if runTest == 1:
                    spinner.stop()
                    scan_stop = time.time()
                    elapsed = scan_stop - scan_start
                    rs_total_elapsed = rs_total_elapsed + elapsed
                    print bcolors.OKBLUE+"\b...Completed in "+display_time(int(elapsed))+bcolors.ENDC+"\n"
                    clear()
                    rs_tool_output_file = open(temp_file).read()
                    if tool_status[tool][arg2] == 0:
                    	if tool_status[tool][arg1].lower() in rs_tool_output_file.lower():
                        	#print "\t"+ vul_info(tool_resp[tool][arg2]) + bcolors.BADFAIL +" "+ tool_resp[tool][arg1] + bcolors.ENDC
                        	vul_remed_info(tool,tool_resp[tool][arg2],tool_resp[tool][arg3])
                        	rs_vul_list.append(tool_names[tool][arg1]+"*"+tool_names[tool][arg2])
                    else:
                    	if any(i in rs_tool_output_file for i in tool_status[tool][arg6]):
                    		m = 1 # This does nothing.
                    	else:
                        	#print "\t"+ vul_info(tool_resp[tool][arg2]) + bcolors.BADFAIL +" "+ tool_resp[tool][arg1] + bcolors.ENDC
                        	vul_remed_info(tool,tool_resp[tool][arg2],tool_resp[tool][arg3])
                        	rs_vul_list.append(tool_names[tool][arg1]+"*"+tool_names[tool][arg2])
            else:
                    runTest = 1
                    spinner.stop()
                    scan_stop = time.time()
                    elapsed = scan_stop - scan_start
                    rs_total_elapsed = rs_total_elapsed + elapsed
                    print bcolors.OKBLUE+"\b\b\b\b...Interrupted in "+display_time(int(elapsed))+bcolors.ENDC+"\n"
                    clear()
                    print "\t"+bcolors.WARNING + "Test Skipped. Performing Next. Press Ctrl+Z to Quit RapidScan." + bcolors.ENDC
                    rs_skipped_checks = rs_skipped_checks + 1

            tool=tool+1

        print bcolors.BG_ENDL_TXT+"[ Preliminary Scan Phase Completed. ]"+bcolors.ENDC
        print "\n"

        #################### Report & Documentation Phase ###########################
        print bcolors.BG_HEAD_TXT+"[ Report Generation Phase Initiated. ]"+bcolors.ENDC
        if len(rs_vul_list)==0:
        	print "\t"+bcolors.OKGREEN+"No Vulnerabilities Detected."+bcolors.ENDC
        else:
        	with open("RS-Vulnerability-Report", "a") as report:
        		while(rs_vul < len(rs_vul_list)):
        			vuln_info = rs_vul_list[rs_vul].split('*')
	        		report.write(vuln_info[arg2])
	        		report.write("\n------------------------\n\n")
	        		temp_report_name = "temp_"+vuln_info[arg1]
	        		with open(temp_report_name, 'r') as temp_report:
	    				data = temp_report.read()
	        			report.write(data)
	        			report.write("\n\n")
	        		temp_report.close()
	       			rs_vul = rs_vul + 1

	       		print "\tComplete Vulnerability Report for "+bcolors.OKBLUE+target+bcolors.ENDC+" named "+bcolors.OKGREEN+"`RS-Vulnerability-Report`"+bcolors.ENDC+" is available under the same directory RapidScan resides."

        	report.close()
        # Writing all scan files output into RS-Debug-ScanLog for debugging purposes.
        for file_index, file_name in enumerate(tool_names):
        	with open("RS-Debug-ScanLog", "a") as report:
        		try:
	        		with open("temp_"+file_name[arg1], 'r') as temp_report:
		    				data = temp_report.read()
		    				report.write(file_name[arg2])
	        				report.write("\n------------------------\n\n")
		        			report.write(data)
		        			report.write("\n\n")
		        	temp_report.close()
	        	except:
	        		break
	        report.close()

        print "\tTotal Number of Vulnerability Checks        : "+bcolors.BOLD+bcolors.OKGREEN+str(len(tool_names))+bcolors.ENDC
        print "\tTotal Number of Vulnerability Checks Skipped: "+bcolors.BOLD+bcolors.WARNING+str(rs_skipped_checks)+bcolors.ENDC
        print "\tTotal Number of Vulnerabilities Detected    : "+bcolors.BOLD+bcolors.BADFAIL+str(len(rs_vul_list))+bcolors.ENDC
        print "\tTotal Time Elapsed for the Scan             : "+bcolors.BOLD+bcolors.OKBLUE+display_time(int(rs_total_elapsed))+bcolors.ENDC
        print "\n"
        print "\tFor Debugging Purposes, You can view the complete output generated by all the tools named "+bcolors.OKBLUE+"`RS-Debug-ScanLog`"+bcolors.ENDC+" under the same directory."
        print bcolors.BG_ENDL_TXT+"[ Report Generation Phase Completed. ]"+bcolors.ENDC

        os.system('setterm -cursor on')
        os.system('rm te* > /dev/null 2>&1') # Clearing previous scan files
