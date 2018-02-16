# rapidscan 

                               __         __
                              /__)_   '_/(  _ _
                             / ( (//)/(/__)( (//)
                                  /
                            =====================
                            
> An automated hybrid security scanner that uses multiple available tools of Kali Linux and ***some custom coded checks*** to scan a target and generate findings spontaneously.
---
### FYI:
- _scanner is still under development and right now supports **21** checks._
- _it is not a multi-threaded program, may be coded in near future._



## Tests For
- :white_check_mark: DNS/HTTP Load Balancers.
- :white_check_mark: Web Application Firewalls.
- :white_check_mark: Checks for Joomla, WordPress and Drupal
- :white_check_mark: SSL Vulnerabilities (_Heartbleed, FREAK, POODLE, CCS Injection, LOGJAM_).
- :white_check_mark: Commonly Opened Ports.
- :white_check_mark: DNS Zone Transfers using multiple tools (_Fierce, DNSWalk_).
- :white_check_mark: Robots.txt and Sitemap Availability.
- & More coming up...

## Usage
**Download the script**
- `wget -O rapidscan.py https://raw.githubusercontent.com/skavngr/rapidscan/master/rapidscan.py`

**Change the executable permission**
- `chmod 777 rapidscan.py`

**Run the script**
- `./rapidscan.py example.com`

## Help
- `--update`: Updates the scanner to latest version.
- `--help`:   Displays the help context.

## Output

![output of rapidscan](https://github.com/skavngr/rapidscan/blob/master/rapidscan.PNG)

## Contribution
- https://gist.github.com/MarcDiethelm/7303312

