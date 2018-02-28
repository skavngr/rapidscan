### Features
- :heavy_exclamation_mark: Check for open directories with Dirbuster: `dirb http://example.com`
- :heavy_exclamation_mark: XSSer Checks: `xsser --all=http://example.com` | Could not find any vulnerability!
- :heavy_exclamation_mark: Golismero SSL Scans: `golismero -e sslscan scan example.com` | Occurrence ID
- :heavy_exclamation_mark: Golismero Zone Transfer: `golismero -e zone_transfer scan example.com` | DNS zone transfer successful
- :heavy_exclamation_mark: Golismero Nikto Scan: `golismero -e nikto scan example.com` | Nikto found 0 vulnerabilities
- :heavy_exclamation_mark: Bruteforcing DNS with Golismero(timeconsuming yellow): `golismero scan example.com -e brute_dns` | Possible subdomain leak
- :heavy_exclamation_mark: Checking zone transfers with DNSenum: `dnsenum google.com` | corrupt (not successful)
- :heavy_exclamation_mark: Subdomain BruteForcing with Fierce: `fierce -dns example.com` | Found 1 entries (usually **www**.example.com) will be included, so have to skip it.
- :heavy_exclamation_mark: Check for emails with Dmitry: `dmitry -e yahoo.com` | Found 0 E-Mail(s)
- :heavy_exclamation_mark: Check for subdomains with Dmitry: `dmitry -s yahoo.com` | Found 0 possible subdomain(s)
- :heavy_exclamation_mark: Checks for WebDAV on home directory: `davtest -url http://192.168.1.209` | SUCCEED
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
- `xsser, golismero, sslyze, bed, doona, grabber, nikto -HELP,` 
- Unavailable Tools: `sublist3r, w3af, goofile`
- `blindElephant.py http://192.168.1.252/wp wordpress` aftermath check
- `dmitry -n example.com` not retrieving.
- `dirbuster -u http://example.com -H` looks for a directory wordlist under the same directory.
- `dnsenum --enum --noreverse example.com` google blocking your queries. (try somewhere else)
- `thc-ssl-dos -l 100 192.168.1.208 443 --accept` gets only ips as input. write an alternative | `dig +short example.com | grep -m 1 ""`
- `wapiti example.com` | does all checks and shows count of each vulnerabilities found in table.
- `doona -t vinothbabu.com -k -m HTTP` | 23/37   [POST / HTTP/1.0XAXAX] .........................................Problem (3) occured with POST / HTTP/1.0XAXAX (965)

### Program Exceptions Checks

- Clear process traces and Ctrl+C hold crashes.
- :thumbsup: ~Implement Keyboard Interrupts and Instant Quit.~
- WARNING: Could not connect (timeout); discarding corresponding tasks. | SSLyze
- [-] Searching in Google:
HTTPConnectionPool(host='www.google.com', port=80): Max retries exceeded with url: /search?num=100&start=0&hl=en&meta=&q=%40%22example.com%22 (Caused by NewConnectionError('<urllib3.connection.HTTPConnection object at 0xb721708c>: Failed to establish a new connection: [Errno -2] Name or service not known',))
