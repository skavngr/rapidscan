### Features

- :heavy_exclamation_mark: Check for emails with Dmitry: `dmitry -e yahoo.com` | Found 0 E-Mail(s)
- :heavy_exclamation_mark: Check for subdomains with Dmitry: `dmitry -s yahoo.com` | Found 0 possible subdomain(s)
- :heavy_exclamation_mark: Check for open directories with Dirbuster: `dirb http://example.com`
- :heavy_exclamation_mark: Checks if domain is spoofed/hijacked: `golismero scan example.com -e dns_malware` | No vulnerabilities found.
- :heavy_exclamation_mark: Checks for WebDAV on home directory: `davtest -url http://192.168.1.209` | SUCCEED
- :thumbsup: ~SSL Compression Enabled: `sslyze --compression target.com` | Compression disabled~
- :heavy_exclamation_mark: Check for git: Do a wget and check for .git under root
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
- xsser, golismero, sslyze, bed, doona, grabber, nikto -HELP, 
- `blindElephant.py http://192.168.1.252/wp wordpress` aftermath check
- `dmitry -n example.com` not retrieving.


### Program Exceptions Checks

- Clear process traces and Ctrl+C hold crashes.
- :thumbsup: ~Implement Keyboard Interrupts and Instant Quit.~
- WARNING: Could not connect (timeout); discarding corresponding tasks. | SSLyze
- [-] Searching in Google:
HTTPConnectionPool(host='www.google.com', port=80): Max retries exceeded with url: /search?num=100&start=0&hl=en&meta=&q=%40%22example.com%22 (Caused by NewConnectionError('<urllib3.connection.HTTPConnection object at 0xb721708c>: Failed to establish a new connection: [Errno -2] Name or service not known',))
