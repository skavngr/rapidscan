### Features (Yet to be added)

- :white_check_mark: ~Check for WordPress: Do a wget with wp-admin and grep the source (check for login/wp-login) curl -s http://somepage.com | grep whatever~
- :white_check_mark: ~Check for Illegal Characters on ASP.Net: /%7C~.aspx~
- :white_check_mark: ~Check for Joomla: Do a wget with administrator and search for joomla~
- :white_check_mark: ~Check for Drupal: Do a wget with user and search for drupal~

- SSL FREAK Check: `nmap  --script ssl-enum-ciphers -p 443` | least strength: broken
- SSL CCS Injection: `nmap -p 443 --script ssl-ccs-injection` | check for Vulnerable
- Slow-loris DoS Check: `nmap -p80,443 --script http-slowloris --max-parallelism 500` | check for Vulnerable
- Poodle Vulnerability Check: `nmap -sV --version-light --script ssl-poodle -p 443`  | check for Vulnerable
- Heartbleed Check with NMap: `nmap -p 443 --script ssl-heartbleed` | check for VULNERABLE
- SSL Compression Enabled: `sslyze --compression target.com` | Compression disabled



### To be checked

- WARNING: Could not connect (timeout); discarding corresponding tasks. | SSLyze
- [-] Searching in Google:
HTTPConnectionPool(host='www.google.com', port=80): Max retries exceeded with url: /search?num=100&start=0&hl=en&meta=&q=%40%22example.com%22 (Caused by NewConnectionError('<urllib3.connection.HTTPConnection object at 0xb721708c>: Failed to establish a new connection: [Errno -2] Name or service not known',))

