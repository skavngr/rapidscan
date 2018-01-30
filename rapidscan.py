#!/usr/bin/python

# Author: Shankar Damodaran
# Tool: Rapidscan v1.0
# Usage: ./rapidscan.py target.com
# Description: This scanner automates the process of vulnerability scanning by using a multitude of available linux security tools. 
#

# Importing the libraries
import sys
import socket
import subprocess
import os
import time
import threading
import collections

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
tool_names = [("wafw00f","Wafw00f - Checks for Application Firewalls"),
              ("nmap","NMap - Fast Scan (Only Few Port Checks)"),
              ("dmitry","Dmitry - Scans for emails using Google's passive search"),
              ("lbd","LBD - Checks for DNS/HTTP Load Balancers")
              ]
tool_names = collections.OrderedDict(tool_names)

# Command that is used to initiate the tool
tool_cmd   = ["wafw00f","nmap -F","theharvester -l 50 -b google -d","lbd"]
# Flags 

# Tool test conditions
tool_cond = ["No WAF",
             "tcp open",
             "[+] Emails found",
             "does NOT use Load-balancing"]
# Tool positive response
tool_pos = ["[+] Web Application Firewall Detected.",
            "[+] Common Ports are Closed.",
            "[+] No Email Addresses Found.",
            "[+] Load Balancer(s) Detected."]
# Tool negative response
tool_neg = ["[-] No Web Application Firewall Detected",
            "[-] Some ports are open. Perform a full-scan manually.",
            "[-] Few email addresses found.",
            "[-] No DNS/HTTP based Load Balancers Found."]

tool = 0

if len(sys.argv)<0 :
    print "[-] Program needs atleast one argument, try again. Quitting now..."
    sys.exit(1)
else:
    target = sys.argv[1]
    os.system('clear')
    os.system('setterm -cursor off')
    print bcolors.BOLD + "RapidScan v1.0 | Initiating tools and scanning parameters for " + target+ "...\n" + bcolors.ENDC
    
    # Creating a temp directory for too reports
    # os.system('mkdir temp')
    
    #for tool in range(0,len(tool_cmd)) :
    for temp_key,temp_val in tool_names.items():
        #print "[:] Deploying "+bcolors.WARNING+tool_names[tool]+bcolors.ENDC
        print "[:] Deploying "+bcolors.WARNING+temp_val+bcolors.ENDC
        spinner.start()
        #temp_file = "temp_"+tool_cmd[tool]
        temp_file = "temp_"+temp_key
        cmd = tool_cmd[tool]+" "+target+" > "+temp_file
        os.system(cmd)
        if tool_cond[tool] not in open(temp_file).read():
            print "\t"+bcolors.OKGREEN + tool_pos[tool] + bcolors.ENDC
        else:
            print "\t"+bcolors.FAIL + tool_neg[tool] + bcolors.ENDC
        spinner.stop()
        tool=tool+1
        #os.system('setterm -cursor on')
        
