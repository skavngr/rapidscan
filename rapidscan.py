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
tool_names = ["Wafw00f","DiG"]
# Command that is used to initiate the tool
tool_cmd   = ["wafw00f","dig"]

tool = 0

if len(sys.argv)<0 :
    print "[-] Program needs atleast one argument, try again. Quitting now..."
    sys.exit(1)
else:
    target = sys.argv[1]
    print "[-] Initiating tools and scanning parameters for " +target+ "..."
    
    #for tool in tool_names:
    for tool in range(0,len(tool_names)):
        print "[-] Deploying "+tool_names[tool]
        spinner.start()
        cmd = tool_cmd[tool]+" "+target+" >temp_"+tool_cmd[tool]
        os.system(cmd)
        spinner.stop()
        tool=tool+1
