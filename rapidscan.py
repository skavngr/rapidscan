#!/usr/bin/python
#                               __         __
#                              /__)_   '_/(  _ _
#                             / ( (//)/(/__)( (//)
#                                  /
#
# Author:      Shankar Damodaran
# Tool:        RapidScan
# Usage: .     /rapidscan.py target.com
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


# RapidScan Help Context
def helper():
        print "\nInformation:"
        print "------------"
        print "./rapidscan.py example.com: Scans the domain example.com"
        print "./rapidscan.py --update   : Updates the scanner to the latest version."
        print "./rapidscan.py --help     : Displays this help context."
        print "\nInteractive:"
        print "-----------"
        print "Ctrl+C: Skips current test."
        print "Ctrl+Z: Quits RapidScan.\n"
   
    
# Initializing the color module class
class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    CLEARLINE = '\033[L'


# Initiliazing the idle loader/spinner class
class Spinner:
    busy = False
    delay = 0.05

    @staticmethod
    def spinning_cursor():
        while 1: 
            for cursor in '|/-\\': yield cursor

    def __init__(self, delay=None):
        self.spinner_generator = self.spinning_cursor()
        if delay and float(delay): self.delay = delay

    def spinner_task(self):
        while self.busy:
            sys.stdout.write(next(self.spinner_generator))
            sys.stdout.flush()
            time.sleep(self.delay)
            sys.stdout.write('\b')
            sys.stdout.flush()

    def start(self):
        self.busy = True
        threading.Thread(target=self.spinner_task).start()

    def stop(self):
        self.busy = False
        time.sleep(self.delay)
# End ofloader/spinner class        

# Instantiating the spinner/loader class
spinner = Spinner()

# Scanners that will be used 
tool_names = [
            ("host","Host - Checks for existence of IPV6 address."),
            ("aspnet_config_err", "ASP.Net Misconfiguration - Checks for ASP.Net Misconfiguration."),
            ("wp_check","WordPress Checker - Checks for WordPress Installation."),
            ("drp_check", "Drupal Checker - Checks for Drupal Installation."),
            ("joom_check", "Joomla Checker - Checks for Joomla Installation."),
            ("uniscan","Uniscan - Checks for robots.txt & sitemap.xml"),
            ("wafw00f","Wafw00f - Checks for Application Firewalls."),
            ("nmap","NMap - Fast Scan (Only Few Port Checks)"),
            ("theharvester","The Harvester - Scans for emails using Google's passive search."),
            ("fierce","Fierce - Attempts Zone Transfer (No Brute Forcing)"),
            ("dnswalk","DNSWalk - Attempts Zone Transfer."),
            ("whois","WHOis - Checks for Administrator's Contact Information."),
            ("nmap_header","NMap (XSS Filter Check) - Checks if XSS Protection Header is present."),
            ("nmap_sloris","NMap (Slowloris DoS) - Checks for Slowloris Denial of Service Vulnerability."),
            ("sslyze","SSLyze - Checks only for Heartbleed Vulnerability."),
            ("nmap_hbleed","NMap (Heartbleed) - Checks only for Heartbleed Vulnerability."),
            ("nmap_poodle","NMap (POODLE) - Checks only for Poodle Vulnerability."),
            ("nmap_ccs","NMap (OpenSSL CCS Injection) - Checks only for CCS Injection."),
            ("nmap_freak","NMap (FREAK) - Checks only for FREAK Vulnerability."),
            ("nmap_logjam","NMap (LOGJAM) - Checks for LOGJAM Vulnerability."),
            ("lbd","LBD - Checks for DNS/HTTP Load Balancers.")
            ]

# Making the dictionary ordered (as it is)           
tool_names = collections.OrderedDict(tool_names)

# Command that is used to initiate the tool (with parameters and extra params)
tool_cmd   = [
                ("host",""),
                ("wget -O temp_aspnet_config_err","/%7C~.aspx"),
                ("wget -O temp_wp_check","/wp-admin"),
                ("wget -O temp_drp_check","/user"),
                ("wget -O temp_joom_check","/administrator"),
                ("uniscan -e -u",""),
                ("wafw00f",""),
                ("nmap -F --open",""),
                ("theharvester -l 50 -b google -d",""),
                ("fierce -wordlist xxx -dns",""),
                ("dnswalk -d","."),
                ("whois",""),
                ("nmap -p80 --script http-security-headers",""),
                ("nmap -p80,443 --script http-slowloris --max-parallelism 500",""),
                ("sslyze --heartbleed",""),
                ("nmap -p 443 --script ssl-heartbleed",""),
                ("nmap -p 443 --script ssl-poodle",""),
                ("nmap -p 443 --script ssl-ccs-injection",""),
                ("nmap -p 443 --script ssl-enum-ciphers",""),
                ("nmap -p 443 --script ssl-dh-params",""),
                ("lbd","")
            ]

# Making the dictionary ordered (as it is)           
tool_cmd = collections.OrderedDict(tool_cmd)

# Tool Responses (Begins)
tool_resp   = [
                ("[+] Has an IPv6 Address.",
                    "[-] Does not have an IPv6 Address. It is good to have one."),
                ("[+] No Misconfiguration Found.",
                    "[-] ASP.Net is misconfigured to throw server stack errors on screen."),
                ("[+] No WordPress Installation Found.",
                    "[-] WordPress Installation Found. Check for vulnerabilities corresponds to that version."),
                ("[+] No Drupal Installation Found.",
                    "[-] Drupal Installation Found. Check for vulnerabilities corresponds to that version."),
                ("[+] No Joomla Installation Found.",
                    "[-] Joomla Installation Found. Check for vulnerabilities corresponds to that version."),
                ("[+] robots.txt/sitemap.xml not Found.",
                    "[-] robots.txt/sitemap.xml found. Check those files for any information."),
                ("[+] Web Application Firewall Detected.",
                    "[-] No Web Application Firewall Detected"),
                ("[+] Common Ports are Closed.",
                    "[-] Some ports are open. Perform a full-scan manually."),
                ("[+] No Email Addresses Found.",
                    "[-] Email Addresses Found."),
                ("[+] Zone Transfer using fierce Failed.",
                    "[-] Zone Transfer Successful using fierce. Reconfigure DNS immediately."),
                ("[+] Zone Transfer using dnswalk Failed.",
                    "[-] Zone Transfer Successful using dnswalk. Reconfigure DNS immediately."),
                ("[+] Whois Information Hidden.",
                    "[-] Whois Information Publicly Available."),
                ("[+] XSS Protection Filter is Enabled.",
                    "[-] XSS Protection Filter is Disabled."),
                ("[+] Not Vulnerable to Slowloris Denial of Service.",
                    "[-] Vulnerable to Slowloris Denial of Service."),
                ("[+] Not Prone to HEARTBLEED Vulnerability.",
                    "[-] HEARTBLEED Vulnerability Found with SSLyze."),
                ("[+] Not Prone to HEARTBLEED Vulnerability.",
                    "[-] HEARTBLEED Vulnerability Found with NMap."),
                ("[+] Not Prone to POODLE Vulnerability.",
                    "[-] POODLE Vulnerability Detected."),
                ("[+] Not Prone to OpenSSL CCS Injection.",
                    "[-] OpenSSL CCS Injection Detected."),
                ("[+] Not Prone to FREAK Vulnerability.",
                    "[-] FREAK Vulnerability Detected."),
                ("[+] Not Prone to LOGJAM Vulnerability.",
                    "[-] LOGJAM Vulnerability Found."),
                ("[+] Load Balancer(s) Detected.",
                    "[-] No DNS/HTTP based Load Balancers Found.")
            ]

# Making the dictionary ordered (as it is)           
tool_resp = collections.OrderedDict(tool_resp)
# Tool Responses (Ends)


# Tool test conditions
tool_cond = [
                "has IPv6",
                "Server Error",
                "wp-login",
                "drupal",
                "joomla",
                "[+]",
                "No WAF",
                "tcp open",
                "No emails found",
                "Whoah, it worked",
                "0 errors",
                "Admin Email:",
                "XSS filter is disabled",
                "vulnerable",
                "Server is vulnerable to Heartbleed",
                "vulnerable",
                "vulnerable",
                "vulnerable",
                "vulnerable",
                "vulnerable",
                "does NOT use Load-balancing"
            ]


# Tool Opcode (If pos fails and you still want to check for another condition)
tool_opcode = [1,0,0,0,0,0,0,0,1,0,0,0,0,0,0,0,0,0,0,0,0]



tool = 0

# Run Test
runTest = 1 

# For accessing tool_cmd dictionary elements
arg1 = 0
arg2 = 1

if len(sys.argv) == 1 :
    helper()
else:
    target = sys.argv[1].lower()
    
    
    if target == '--update':
        print "RapidScan is updating.. Please wait..."
        spinner.start()
        os.system('wget -N https://raw.githubusercontent.com/skavngr/rapidscan/master/rapidscan.py -O rapidscan.py > /dev/null 2>&1')
        spinner.stop()
        print "RapidScan updated to latest version."
        sys.exit(1)
        
    elif target == '--help':
        helper()
        sys.exit(1)
    else:
    
        os.system('rm te*') # Clearing previous scan files
        os.system('clear')
        os.system('setterm -cursor off')
        
        print bcolors.BOLD + "RapidScan | Initiating tools and scanning procedures for " + target+ "...\n" + bcolors.ENDC
        
        print("""\
                                  __         __
                                 /__)_   '_/(  _ _
                                / ( (//)/(/__)( (//)
                                     /
                                ====================
                            
                            """)

        
        for temp_key,temp_val in tool_names.items():
            print "[:] Deploying "+bcolors.WARNING+temp_val+bcolors.ENDC
            spinner.start()
            temp_file = "temp_"+temp_key
            cmd = tool_cmd.items()[tool][arg1]+" "+target+tool_cmd.items()[tool][arg2]+" > "+temp_file+" 2>&1"
           
            try:
                subprocess.check_output(cmd, shell=True)
            except KeyboardInterrupt:
                runTest = 0
            except:
                runTest = 1
                
            if runTest == 1:
                spinner.stop()
                
                if tool_cond[tool] not in open(temp_file).read():
                    if tool_opcode[tool] == 0:
                        #print bcolors.CLEARLINE
                        print "\t"+bcolors.OKGREEN + tool_resp.items()[tool][arg1] + bcolors.ENDC
                    else:
                        #print bcolors.CLEARLINE
                        print "\t"+bcolors.FAIL + tool_resp.items()[tool][arg2] + bcolors.ENDC
                else:
                    if tool_opcode[tool] == 1:
                        #print bcolors.CLEARLINE
                        print "\t"+bcolors.OKGREEN + tool_resp.items()[tool][arg1] + bcolors.ENDC
                    else:
                        #print bcolors.CLEARLINE
                        print "\t"+bcolors.FAIL + tool_resp.items()[tool][arg2] + bcolors.ENDC
            else:
                
                #print "\033[K", "\r"
                #sys.stdout.flush()
                print "\t"+bcolors.BOLD + "Test Skipped. Performing Next. Press Ctrl+Z to Quit RapidScan." + bcolors.ENDC
                
                runTest = 1
                spinner.stop()
            
            tool=tool+1
            
        os.system('setterm -cursor on')
        os.system('rm te*') # Clearing previous scan files

