### Tool Deployment (on various OS flavours)
**Ubuntu**
- `apt-key update && apt-get update`
- `apt-get install whois --force-yes`

### Features
- :thumbsup: ~WhatWeb X-XSS Protection Header Check: `whatweb example.com -a 1` | X-XSS-Protection[1~
- :thumbsup: ~Nmap IIS WebDav: `nmap -T4 -p80 --script=http-iis-webdav-vuln <host>` | WebDAV is ENABLED~
- :thumbsup: ~Wapiti Checks: `wapiti <host> -f txt -o temp_wapiti` | Host:~
- :thumbsup: ~Nmap SMB UDP Check: `nmap -p137,138 --open <host>` | /open~
- :thumbsup: ~Nmap SMB TCP Check: `nmap -p445,137-139 --open <host>` | /open tcp~
- :thumbsup: ~ASP.Net Elmah AXD: `wget -O temp_aspnet_elmah_axd /elmah.axd` | Microsoft SQL Server Error Log~
- :thumbsup: ~Nmap SNMP Check: `nmap -p161 -sU --open <host>` | 161/open udp~
- :thumbsup: ~Nmap Full UDP Port Scan: `nmap -p1-65535 -sU --open <host>` | /open~
- :thumbsup: ~Nmap Full TCP Port Scan: `nmap -p1-65535 --open <host>` | /open tcp~
- :thumbsup: ~Nmap RDP TCP Check: `nmap -p3389 --open -sT <host>` | 3389/open tcp~
- :thumbsup: ~Nmap RDP UDP Check: `nmap -p3389 --open -sU <host>` | 3389/open udp~
- :thumbsup: ~Nmap ORACLE Check: `nmap -p1521 --open <host>` | 1521/open tcp~
- :thumbsup: ~Nmap MySQL Check: `nmap -p3306 --open <host>` | 3306/open tcp~
- :thumbsup: ~Nmap MS-SQL Server Check: `nmap -p1433 --open <host>` | 1433/open tcp~
- :thumbsup: ~Nmap TELNET Check: `nmap -p23 --open <host>` | 23/open tcp~
- :thumbsup: ~Nmap FTP Check: `nmap -p21 --open <host>` | 21/open tcp~
- :thumbsup: ~Nmap STUXNET Check: `nmap --script stuxnet-detect -p 445 <host>` | 445/open tcp~
- :thumbsup: ~Checks for WebDAV on home directory: `davtest -url http://192.168.1.209` | SUCCEED~
- :thumbsup: ~Golismero Webservers Fingerprint: `golismero -e fingerprint_web scan example.com` | No vulnerabilities found.~
- :thumbsup: ~Uniscan File Brute Forcer: `uniscan -w -u example.com` | [+]~
- :thumbsup: ~Uniscan Directory Brute Forcer: `uniscan -q -u example.com` | [+]~
- :thumbsup: ~Uniscan Mini Stress Tester: `uniscan -r -u example.com` | [+]~
- :thumbsup: ~Uniscan Checks for LFI, RFI and RCE: `uniscan -s -u example.com` | [+]~
- :thumbsup: ~Uniscan Checks for XSS, SQLi, BSQLi & a few checks: `uniscan -d -u example.com` | [+]~
- :thumbsup: ~Nikto XSS Expect Header Check: `nikto -Plugins "apache_expect_xss" -host example.com` | 0 item(s) reported~
- :thumbsup: ~Nikto Subdomain Bruter: `nikto -Plugins "subdomain" -host example.com` | 0 item(s) reported~
- :thumbsup: ~Nikto ShellShock Bug Check: `nikto -Plugins "shellshock" -host example.com` | 0 item(s) reported~
- :thumbsup: ~Nikto Internal IP Leak: `nikto -Plugins "cookies" -host example.com` | 0 item(s) reported~
- :thumbsup: ~Nikto HTTP PUT DEL Test: `nikto -Plugins "put_del_test" -host example.com` | 0 item(s) reported~
- :thumbsup: ~Nikto Headers Check: `nikto -Plugins "headers" -host example.com` | 0 item(s) reported~
- :thumbsup: ~Nikto MS10-070 Check: `nikto -Plugins "ms10-070" -host example.com` | 0 item(s) reported~
- :thumbsup: ~Nikto Server Issues: `nikto -Plugins "msgs" -host example.com` | 0 item(s) reported~
- :thumbsup: ~Nikto Server Outdated Checks: `nikto -Plugins "outdated" -host example.com` | 0 item(s) reported~
- :thumbsup: ~Nikto HTTP Options Checks: `nikto -Plugins "httpoptions" -host example.com` | 0 item(s) reported~
- :thumbsup: ~Nikto CGI Directories Enum: `nikto -Plugins "cgi" -host example.com` | 0 item(s) reported~
- :thumbsup: ~Nikto SSL Checks: `nikto -Plugins "ssl" -host example.com` | 0 item(s) reported~
- :thumbsup: ~Nikto File Checks: `nikto -Plugins "sitefiles" -host example.com` | 0 item(s) reported~
- :thumbsup: ~Nikto Injectable Paths: `nikto -Plugins "paths" -host example.com` | 0 item(s) reported~
- :thumbsup: ~Subdomains brute force with DNSMap: `dnsmap example.com` | #1~
- :thumbsup: ~Check for open directories with Dirbuster: `dirb http://example.com`~
- :thumbsup: ~XSSer Checks: `xsser --all=http://example.com` | Could not find any vulnerability!~
- :thumbsup: ~Golismero SSL Scans: `golismero -e sslscan scan example.com` | Occurrence ID~
- :thumbsup: ~Golismero Zone Transfer: `golismero -e zone_transfer scan example.com` | DNS zone transfer successful~
- :thumbsup: ~Golismero Nikto Scan: `golismero -e nikto scan example.com` | Nikto found 0 vulnerabilities~
- :thumbsup: ~Bruteforcing DNS with Golismero(timeconsuming yellow): `golismero scan example.com -e brute_dns` | Possible subdomain leak~
- :thumbsup: ~Checking zone transfers with DNSenum: `dnsenum google.com` | corrupt (not successful)~
- :thumbsup: ~Subdomain BruteForcing with Fierce: `fierce -dns example.com` | Found 1 entries (usually **www**.example.com) will be included, so have to skip it.~
- :thumbsup: ~Check for emails with Dmitry: `dmitry -e yahoo.com` | Found 0 E-Mail(s)~
- :thumbsup: ~Check for subdomains with Dmitry: `dmitry -s yahoo.com` | Found 0 possible subdomain(s)~
- :thumbsup: ~Golismero Brute Force Directories: `golismero -e brute_directories scan example.com` | No vulnerabilities found.~
- :thumbsup: ~Golismero SQLMap: `golismero -e sqlmap scan example.com` | No vulnerabilities found.~
- :thumbsup: ~Golismero Brute URL Predictables: `golismero -e brute_url_predictables scan example.com` | No vulnerabilities found.~
- :thumbsup: ~Golismero HeartBleed Check: `golismero -e heartbleed scan example.com` | No vulnerabilities found.~
- :thumbsup: ~Checks if domain is spoofed/hijacked: `golismero scan example.com -e dns_malware` | No vulnerabilities found.~
- :thumbsup: ~SSL Compression Enabled: `sslyze --compression target.com` | Compression disabled~
- :thumbsup: ~Check for WordPress: Do a wget with wp-admin and grep the source (check for login/wp-login) curl -s http://somepage.com | grep whatever~
- :thumbsup: ~Check for Illegal Characters on ASP.Net: /%7C~.aspx~
- :thumbsup: ~Check for Joomla: Do a wget with administrator and search for joomla~
- :thumbsup: ~Check for Drupal: Do a wget with user and search for drupal~
- :thumbsup: ~SSL FREAK Check: `nmap  --script ssl-enum-ciphers -p 443` | least strength: broken~
- :thumbsup: ~SSL CCS Injection: `nmap -p 443 --script ssl-ccs-injection` | check for Vulnerable~
- :thumbsup: ~Slow-loris DoS Check: `nmap -p80,443 --script http-slowloris --max-parallelism 500` | check for Vulnerable~
- :thumbsup: ~Poodle Vulnerability Check: `nmap -sV --version-light --script ssl-poodle -p 443`  | check for Vulnerable~
- :thumbsup: ~Heartbleed Check with NMap: `nmap -p 443 --script ssl-heartbleed` | check for VULNERABLE~

### Dig Deeper
- if snmp found, do `braa`
- research `dnsmap` log for internal ip leak. [+] 20 (sub)domains and 20 IP address(es) found [+] 4 internal IP address(es) disclosed [+] completion time: 1568 second(s)
- `amap, xsser, golismero, sslyze, bed, doona, grabber, nikto -HELP,` 
- Unavailable Tools: `sublist3r, w3af, goofile, crowbar`
- `blindElephant.py http://192.168.1.252/wp wordpress` aftermath check
- `dmitry -n example.com` not retrieving.
- `dirbuster -u http://example.com -H` looks for a directory wordlist under the same directory.
- `dnsenum --enum --noreverse example.com` google blocking your queries. (try somewhere else)
- `thc-ssl-dos -l 100 192.168.1.208 443 --accept` gets only ips as input. write an alternative | `dig +short example.com | grep -m 1 ""`
- `doona -t example.com -k -m HTTP` | 23/37   [POST / HTTP/1.0XAXAX] .........................................Problem (3) occured with POST / HTTP/1.0XAXAX (965)

### Program Exceptions Checks

- :thumbsup: ~Clear process traces and Ctrl+C hold crashes.~
- :thumbsup: ~Implement Keyboard Interrupts and Instant Quit.~
