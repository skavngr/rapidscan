### Features (Yet to be added)

- ~Check for WordPress: Do a wget with wp-admin and grep the source (check for login/wp-login) curl -s http://somepage.com | grep whatever~
- ~Check for Illegal Characters on ASP.Net: /%7C~.aspx~
- ~Check for Joomla: Do a wget with administrator and search for joomla~
- ~Check for Drupal: Do a wget with user and search for drupal~
- Slow-loris DoS Check: nmap -p80,443 --script http-slowloris --max-parallelism 500 | check for Vulnerable
- Poodle Vulnerability Check: nmap -sV --version-light --script ssl-poodle -p 443  | check for Vulnerable


### To be checked

- WARNING: Could not connect (timeout); discarding corresponding tasks. | SSLyze
- [-] Searching in Google:
HTTPConnectionPool(host='www.google.com', port=80): Max retries exceeded with url: /search?num=100&start=0&hl=en&meta=&q=%40%22example.com%22 (Caused by NewConnectionError('<urllib3.connection.HTTPConnection object at 0xb721708c>: Failed to establish a new connection: [Errno -2] Name or service not known',))

