#!/usr/bin/python
# -*- coding: utf-8 -*-
#                               __         __
#                              /__)_   '_/(  _ _
#                             / ( (//)/(/__)( (//)
#                                  /
#
# Author:      Shankar Damodaran
# Tool:        RapidScan
# Usage:       ./rapidscan.py example.com (or) python rapidsan.py example.com
# Description: This scanner automates the process of security scanning by using a 
#              multitude of available linux security tools and some custom scripts. 
#

# Importing the libraries
import sys
import socket
import subprocess
import os
import time
import threading
import collections
import signal
import random


# Scan Time Elapser
intervals = (
    ('h', 3600),    
    ('m', 60),
    ('s', 1),
    )

def display_time(seconds, granularity=3):
    result = []

    for name, count in intervals:
        value = seconds // count
        if value:
            seconds -= value * count
            result.append("{}{}".format(value, name))
    return ' '.join(result[:granularity])


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
    CRIT_BG = '\033[41m'
    SAFE_BG = '\033[42m'
    MEDIUM_BG = '\033[43m'
    LOW_BG = '\033[44m'
    

# Legends  
proc_high = bcolors.BADFAIL + "●" + bcolors.ENDC
proc_med  = bcolors.WARNING + "●" + bcolors.ENDC
proc_low  = bcolors.OKGREEN + "●" + bcolors.ENDC


# RapidScan Help Context
def helper():
        print "\n\tInformation:"
        print "\t-------------"
        print "\t./rapidscan.py example.com: Scans the domain example.com"
        print "\t./rapidscan.py --update   : Updates the scanner to the latest version."
        print "\t./rapidscan.py --help     : Displays this help context."
        print "\n\tInteractive:"
        print "\t------------"
        print "\tCtrl+C: Skips current test."
        print "\tCtrl+Z: Quits RapidScan."
        print "\n\tLegends:"
        print "\t--------"
        print "\t["+proc_high+"]: Scan process may take longer times (not predictable)."
        print "\t["+proc_med+"]: Scan process may take less than 10 minutes."
        print "\t["+proc_low+"]: Scan process may take less than a minute or two.\n"
        

# Clears Line
def clear():
        sys.stdout.write("\033[F")
        sys.stdout.write("\033[K") 
 

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
                sys.stdout.write(next(self.spinner_generator))
                sys.stdout.flush()
                time.sleep(self.delay)
                sys.stdout.write('\b')
                sys.stdout.flush()
        except (KeyboardInterrupt, SystemExit):
            #clear()
            print "\n\t"+ bcolors.CRIT_BG+"RapidScan received a series of Ctrl+C hits. Quitting..." +bcolors.ENDC
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
            print "\n\t"+ bcolors.CRIT_BG+"RapidScan received a series of Ctrl+C hits. Quitting..." +bcolors.ENDC
            sys.exit(1)
# End ofloader/spinner class        

# Instantiating the spinner/loader class
spinner = Spinner()

# Scanners that will be used and filename rotation 
tool_names = [
                ["host","Host - Checks for existence of IPV6 address."],
                ["aspnet_config_err","ASP.Net Misconfiguration - Checks for ASP.Net Misconfiguration."],
                ["wp_check","WordPress Checker - Checks for WordPress Installation."],
                ["drp_check", "Drupal Checker - Checks for Drupal Installation."],
                ["joom_check", "Joomla Checker - Checks for Joomla Installation."],
                ["uniscan","Uniscan - Checks for robots.txt & sitemap.xml"],
                ["wafw00f","Wafw00f - Checks for Application Firewalls."],
                ["nmap","Nmap - Fast Scan [Only Few Port Checks]"],
                ["theharvester","The Harvester - Scans for emails using Google's passive search."],
                ["dnsrecon","DNSRecon - Attempts Multiple Zone Transfers on Nameservers."],
                ["fierce","Fierce - Attempts Zone Transfer [No Brute Forcing]"],
                ["dnswalk","DNSWalk - Attempts Zone Transfer."],
                ["whois","WHOis - Checks for Administrator's Contact Information."],
                ["nmap_header","Nmap [XSS Filter Check] - Checks if XSS Protection Header is present."],
                ["nmap_sloris","Nmap [Slowloris DoS] - Checks for Slowloris Denial of Service Vulnerability."],
                ["sslyze_hbleed","SSLyze - Checks only for Heartbleed Vulnerability."],
                ["nmap_hbleed","Nmap [Heartbleed] - Checks only for Heartbleed Vulnerability."],
                ["nmap_poodle","Nmap [POODLE] - Checks only for Poodle Vulnerability."],
                ["nmap_ccs","Nmap [OpenSSL CCS Injection] - Checks only for CCS Injection."],
                ["nmap_freak","Nmap [FREAK] - Checks only for FREAK Vulnerability."],
                ["nmap_logjam","Nmap [LOGJAM] - Checks for LOGJAM Vulnerability."],
                ["sslyze_ocsp","SSLyze - Checks for OCSP Stapling."],
                ["sslyze_zlib","SSLyze - Checks for ZLib Deflate Compression."],
                ["sslyze_reneg","SSLyze - Checks for Secure Renegotiation Support and Client Renegotiation."],
                ["sslyze_resum","SSLyze - Checks for Session Resumption Support with [Session IDs/TLS Tickets]."],
                ["lbd","LBD - Checks for DNS/HTTP Load Balancers."],
                ["golismero_dns_malware","Golismero - Checks if the domain is spoofed or hijacked."],
                ["golismero_heartbleed","Golismero - Checks only for Heartbleed Vulnerability."],
                ["golismero_brute_url_predictables","Golismero - BruteForces for certain files on the Domain."],
                ["golismero_brute_directories","Golismero - BruteForces for certain directories on the Domain."],
                ["golismero_sqlmap","Golismero - SQLMap [Retrieves only the DB Banner]"],
                ["dirb","DirB - Brutes the target for Open Directories."],
                ["xsser","XSSer - Checks for Cross-Site Scripting [XSS] Attacks."],
                ["golismero_ssl_scan","Golismero SSL Scans - Performs SSL related Scans."],
                ["golismero_zone_transfer","Golismero Zone Transfer - Attempts Zone Transfer."],
                ["golismero_nikto","Golismero Nikto Scans - Uses Nikto Plugin to detect vulnerabilities."],
                ["golismero_brute_subdomains","Golismero Subdomains Bruter - Brute Forces Subdomain Discovery."],
                ["dnsenum_zone_transfer","DNSEnum - Attempts Zone Transfer."],
                ["fierce_brute_subdomains","Fierce Subdomains Bruter - Brute Forces Subdomain Discovery."],
                ["dmitry_email","DMitry - Passively Harvests Emails from the Domain."],
                ["dmitry_subdomains","DMitry - Passively Harvests Subdomains from the Domain."],
                ["nmap_telnet","Nmap [TELNET] - Checks if TELNET service is running."],
                ["nmap_ftp","Nmap [FTP] - Checks if FTP service is running."],
                ["nmap_stuxnet","Nmap [STUXNET] - Checks if the host is affected by STUXNET Worm."],
                ["webdav","WebDAV - Checks if WEBDAV enabled on Home directory."],
                ["golismero_finger","Golismero - Does a fingerprint on the Domain."],
                ["uniscan_filebrute","Uniscan - Brutes for Filenames on the Domain."],
                ["uniscan_dirbrute", "Uniscan - Brutes Directories on the Domain."],
                ["uniscan_ministresser", "Uniscan - Stress Tests the Domain."],
                ["uniscan_rfi","Uniscan - Checks for LFI, RFI and RCE."],#50
                ["uniscan_xss","Uniscan - Checks for XSS, SQLi, BSQLi & Other Checks."],
                ["nikto_xss","Nikto - Checks for Apache Expect XSS Header."],
                ["nikto_subrute","Nikto - Brutes Subdomains."],
                ["nikto_shellshock","Nikto - Checks for Shellshock Bug."],
                ["nikto_internalip","Nikto - Checks for Internal IP Leak."],
                ["nikto_putdel","Nikto - Checks for HTTP PUT DEL."],
                ["nikto_headers","Nikto - Checks the Domain Headers."],
                ["nikto_ms01070","Nikto - Checks for MS10-070 Vulnerability."],
                ["nikto_servermsgs","Nikto - Checks for Server Issues."],
                ["nikto_outdated","Nikto - Checks if Server is Outdated."],
                ["nikto_httpoptions","Nikto - Checks for HTTP Options on the Domain."],
                ["nikto_cgi","Nikto - Enumerates CGI Directories."],
                ["nikto_ssl","Nikto - Performs SSL Checks."],
                ["nikto_sitefiles","Nikto - Checks for any interesting files on the Domain."],
                ["nikto_paths","Nikto - Checks for Injectable Paths."],
                ["dnsmap_brute","DNSMap - Brutes Subdomains."]
            ]




# Command that is used to initiate the tool (with parameters and extra params)
tool_cmd   = [
                ["host ",""],
                ["wget -O temp_aspnet_config_err ","/%7C~.aspx"],
                ["wget -O temp_wp_check ","/wp-admin"],
                ["wget -O temp_drp_check ","/user"],
                ["wget -O temp_joom_check ","/administrator"],
                ["uniscan -e -u ",""],
                ["wafw00f ",""],
                ["nmap -F --open ",""],
                ["theharvester -l 50 -b google -d ",""],
                ["dnsrecon -d ",""],
                ["fierce -wordlist xxx -dns ",""],
                ["dnswalk -d ","."],
                ["whois ",""],
                ["nmap -p80 --script http-security-headers ",""],
                ["nmap -p80,443 --script http-slowloris --max-parallelism 500 ",""],
                ["sslyze --heartbleed ",""],
                ["nmap -p443 --script ssl-heartbleed ",""],
                ["nmap -p443 --script ssl-poodle ",""],
                ["nmap -p443 --script ssl-ccs-injection ",""],
                ["nmap -p443 --script ssl-enum-ciphers ",""],
                ["nmap -p443 --script ssl-dh-params ",""],
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
                ["nmap -p23 --open ",""],
                ["nmap -p21 --open ",""],
                ["nmap --script stuxnet-detect -p 445 ",""],
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
                ["dnsmap ",""]
            ]


# Tool Responses (Begins)
tool_resp   = [
                ["[-] Does not have an IPv6 Address. It is good to have one."],
                ["[-] ASP.Net is misconfigured to throw server stack errors on screen."],
                ["[-] WordPress Installation Found. Check for vulnerabilities corresponds to that version."],
                ["[-] Drupal Installation Found. Check for vulnerabilities corresponds to that version."],
                ["[-] Joomla Installation Found. Check for vulnerabilities corresponds to that version."],
                ["[-] robots.txt/sitemap.xml found. Check those files for any information."],
                ["[-] No Web Application Firewall Detected"],
                ["[-] Some ports are open. Perform a full-scan manually."],
                ["[-] Email Addresses Found."],
                ["[-] Zone Transfer Successful using DNSRecon. Reconfigure DNS immediately."],
                ["[-] Zone Transfer Successful using fierce. Reconfigure DNS immediately."],
                ["[-] Zone Transfer Successful using dnswalk. Reconfigure DNS immediately."],
                ["[-] Whois Information Publicly Available."],
                ["[-] XSS Protection Filter is Disabled."],
                ["[-] Vulnerable to Slowloris Denial of Service."],
                ["[-] HEARTBLEED Vulnerability Found with SSLyze."],
                ["[-] HEARTBLEED Vulnerability Found with Nmap."],
                ["[-] POODLE Vulnerability Detected."],
                ["[-] OpenSSL CCS Injection Detected."],
                ["[-] FREAK Vulnerability Detected."],
                ["[-] LOGJAM Vulnerability Detected."],
                ["[-] Unsuccessful OCSP Response."],
                ["[-] Server supports Deflate Compression."],
                ["[-] Secure Renegotiation is unsupported."],
                ["[-] Secure Resumption unsupported with (Sessions IDs/TLS Tickets)."],
                ["[-] No DNS/HTTP based Load Balancers Found."],
                ["[-] Domain is spoofed/hijacked."],
                ["[-] HEARTBLEED Vulnerability Found with Golismero."],
                ["[-] Open Files Found with Golismero BruteForce."],
                ["[-] Open Directories Found with Golismero BruteForce."],
                ["[-] DB Banner retrieved with SQLMap."],
                ["[-] Open Directories Found with DirB."],
                ["[-] XSSer found XSS vulnerabilities."],
                ["[-] Found SSL related vulnerabilities with Golismero."],
                ["[-] Zone Transfer Successful with Golismero. Reconfigure DNS immediately."],
                ["[-] Golismero Nikto Plugin found vulnerabilities."],
                ["[-] Found Subdomains with Golismero."],
                ["[-] Zone Transfer Successful using DNSEnum. Reconfigure DNS immediately."],
                ["[-] Found Subdomains with Fierce."],
                ["[-] Email Addresses discovered with DMitry."],
                ["[-] Subdomains discovered with DMitry."],
                ["[-] Telnet Service Detected."],
                ["[-] FTP Service Detected."],
                ["[-] Vulnerable to STUXNET."],
                ["[-] WebdAV Enabled."],
                ["[-] Found some vulnerabilities."],
                ["[-] Open Files Found with Uniscan."],
                ["[-] Open Directories Found with Uniscan."],
                ["[-] Vulnerable to Stress Tests."],
                ["[-] Uniscan detected possible LFI, RFI or RCE."],
                ["[-] Uniscan detected possible XSS, SQLi, BSQLi."],
                ["[-] Apache Expect XSS Header not present."],
                ["[-] Found Subdomains with Nikto."],
                ["[-] Webserver vulnerable to Shellshock Bug."],
                ["[-] Webserver leaks Internal IP."],
                ["[-] HTTP PUT DEL Methods Enabled."],
                ["[-] Some vulnerable headers exposed."],
                ["[-] Webserver vulnerable to MS10-070."],
                ["[-] Some issues found on the Webserver."],
                ["[-] Webserver is Outdated."],
                ["[-] Some issues found with HTTP Options."],
                ["[-] CGI Directories Enumerated."],
                ["[-] Vulnerabilities reported in SSL Scans."],
                ["[-] Interesting Files Detected."],
                ["[-] Injectable Paths Detected."],
                ["[-] Found Subdomains with DNSMap."]
                
            ]

# Tool Responses (Ends)



# Tool Status (Reponse Data + Response Code (if status check fails and you still got to push it + Legends)
tool_status = [
                ["has IPv6",1,proc_low," < 15s","ipv6"],
                ["Server Error",0,proc_low," < 30s","asp.netmisconf"],
                ["wp-login",0,proc_low," < 30s","wpcheck"],
                ["drupal",0,proc_low," < 30s","drupalcheck"],
                ["joomla",0,proc_low," < 30s","joomlacheck"],
                ["[+]",0,proc_low," < 40s","robotscheck"],
                ["No WAF",0,proc_low," < 45s","wafcheck"],
                ["tcp open",0,proc_med," <  2m","nmapopen"],
                ["No emails found",1,proc_med," <  3m","harvester"],
                ["[+] Zone Transfer was successful!!",0,proc_low," < 20s","dnsreconzt"],
                ["Whoah, it worked",0,proc_low," < 30s","fiercezt"],
                ["0 errors",0,proc_low," < 35s","dnswalkzt"],
                ["Admin Email:",0,proc_low," < 25s","whois"],
                ["XSS filter is disabled",0,proc_low," < 20s","nmapxssh"],
                ["vulnerable",0,proc_high," < 45m","nmapdos"],
                ["Server is vulnerable to Heartbleed",0,proc_low," < 40s","sslyzehb"],
                ["vulnerable",0,proc_low," < 30s","nmap1"],
                ["vulnerable",0,proc_low," < 35s","nmap2"],
                ["vulnerable",0,proc_low," < 35s","nmap3"],
                ["vulnerable",0,proc_low," < 30s","nmap4"],
                ["vulnerable",0,proc_low," < 35s","nmap5"],
                ["ERROR - OCSP response status is not successful",0,proc_low," < 25s","sslyze1"],
                ["VULNERABLE - Server supports Deflate compression",0,proc_low," < 30s","sslyze2"],
                ["vulnerable",0,proc_low," < 25s","sslyze3"],
                ["vulnerable",0,proc_low," < 30s","sslyze4"],
                ["does NOT use Load-balancing",0,proc_med," <  4m","lbd"],
                ["No vulnerabilities found",1,proc_low," < 45s","golism1"],
                ["No vulnerabilities found",1,proc_low," < 40s","golism2"],
                ["No vulnerabilities found",1,proc_low," < 45s","golism3"],
                ["No vulnerabilities found",1,proc_low," < 40s","golism4"],
                ["No vulnerabilities found",1,proc_low," < 45s","golism5"],
                ["FOUND: 0",1,proc_high," < 35m","dirb"],
                ["Could not find any vulnerability!",1,proc_med," <  4m","xsser"],
                ["Occurrence ID",0,proc_low," < 45s","golism6"],
                ["DNS zone transfer successful",0,proc_low," < 30s","golism7"],
                ["Nikto found 0 vulnerabilities",1,proc_med," <  4m","golism8"],
                ["Possible subdomain leak",0,proc_high," < 30m","golism9"],
                ["AXFR record query failed:",1,proc_low," < 45s","dnsenumzt"],
                ["Found 1 entries",1,proc_high," < 75m","fierce2"],
                ["Found 0 E-Mail(s)",1,proc_low," < 30s","dmitry1"],
                ["Found 0 possible subdomain(s)",1,proc_low," < 35s","dmitry2"],
                ["23/open tcp",0,proc_low," < 15s","nmaptelnet"],
                ["21/open tcp",0,proc_low," < 15s","nmapftp"],
                ["445/open tcp",0,proc_low," < 20s","nmapstux"],
                ["SUCCEED",0,proc_low," < 30s","webdav"],
                ["No vulnerabilities found.",1,proc_low," < 15s","golism10"],
                ["[+]",0,proc_med," <  2m","uniscan2"],
                ["[+]",0,proc_med," <  5m","uniscan3"],
                ["[+]",0,proc_med," <  9m","uniscan4"],
                ["[+]",0,proc_med," <  8m","uniscan5"],
                ["[+]",0,proc_med," <  9m","uniscan6"],
                ["0 item(s) reported",1,proc_low," < 35s","nikto1"],
                ["0 item(s) reported",1,proc_low," < 35s","nikto2"],
                ["0 item(s) reported",1,proc_low," < 35s","nikto3"],
                ["0 item(s) reported",1,proc_low," < 35s","nikto4"],
                ["0 item(s) reported",1,proc_low," < 35s","nikto5"],
                ["0 item(s) reported",1,proc_low," < 35s","nikto6"],
                ["0 item(s) reported",1,proc_low," < 35s","nikto7"],
                ["0 item(s) reported",1,proc_low," < 35s","nikto8"],
                ["0 item(s) reported",1,proc_low," < 35s","nikto9"],
                ["0 item(s) reported",1,proc_low," < 35s","nikto10"],
                ["0 item(s) reported",1,proc_low," < 35s","nikto11"],
                ["0 item(s) reported",1,proc_low," < 35s","nikto12"],
                ["0 item(s) reported",1,proc_low," < 35s","nikto13"],
                ["0 item(s) reported",1,proc_low," < 35s","nikto14"],
                ["#1",0,proc_high," < 30m","dnsmap_brute"]
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

if len(sys.argv) == 1 :
    helper()
else:
    target = sys.argv[1].lower()
    
    
    if target == '--update' or target == '-u' or target == '--u':
        print "RapidScan is updating....Please wait.\n"
        spinner.start()
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
        helper()
        sys.exit(1)
    else:
    
        os.system('rm te*') # Clearing previous scan files
        os.system('clear')
        os.system('setterm -cursor off')
        
        #print bcolors.BOLD + "RapidScan | Initiating tools and scanning procedures for " + target+ "...\n" 
        print bcolors.WARNING
        print("""\
                                  __         __
                                 /__)_  """+bcolors.BADFAIL+" ●"+bcolors.WARNING+"""_/(  _ _
                                / ( (//)/(/__)( (//)
                                     /
                     """+bcolors.ENDC+"""(The Multi-Tool Web Vulnerability Scanner)                
                            """)

        print bcolors.ENDC
        print bcolors.LOW_BG+"[ Scan Phase Initiated... Loaded "+str(tool_checks)+" vulnerability checks.  ]"+bcolors.ENDC
        while(tool < len(tool_names)):    
            print "["+tool_status[tool][arg3]+tool_status[tool][arg4]+"] Deploying "+str(tool+1)+"/"+str(tool_checks)+" | "+bcolors.OKBLUE+tool_names[tool][arg2]+bcolors.ENDC,
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
                    print bcolors.OKBLUE+"...Completed in "+display_time(int(elapsed))+bcolors.ENDC+"\n"
                    clear()
                    if tool_status[tool][arg1] not in open(temp_file).read():
                        if tool_status[tool][arg2] == 1:
                            print "\t"+bcolors.BADFAIL + tool_resp[tool][arg1] + bcolors.ENDC
                    else:
                        if tool_status[tool][arg2] == 0:
                            print "\t"+bcolors.BADFAIL + tool_resp[tool][arg1] + bcolors.ENDC
            else:
                    runTest = 1
                    spinner.stop()
                    scan_stop = time.time()
                    elapsed = scan_stop - scan_start
                    print bcolors.OKBLUE+"\b\b\b...Interrupted in "+display_time(int(elapsed))+bcolors.ENDC+"\n"
                    clear()
                    print "\t"+bcolors.WARNING + "Test Skipped. Performing Next. Press Ctrl+Z to Quit RapidScan." + bcolors.ENDC                
                        
            tool=tool+1
            
        os.system('setterm -cursor on')
        os.system('rm te*') # Clearing previous scan files


            