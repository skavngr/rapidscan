[![GitHub issues](https://img.shields.io/github/issues/skavngr/rapidscan.svg)](https://github.com/skavngr/rapidscan/issues)
[![GitHub forks](https://img.shields.io/github/forks/skavngr/rapidscan.svg)](https://github.com/skavngr/rapidscan/network)
[![GitHub stars](https://img.shields.io/github/stars/skavngr/rapidscan.svg)](https://github.com/skavngr/rapidscan/stargazers)
[![GitHub license](https://img.shields.io/github/license/skavngr/rapidscan.svg)](https://github.com/skavngr/rapidscan/blob/master/LICENSE)

# rapidscan 

                               __         __
                              /__)_   '_/(  _ _
                             / ( (//)/(/__)( (//)
                                  /
                            =====================
                            
## Evolution:
> Being a pentester for years, sometimes its quite a fuss to run different security scanning tools and there are chances you may miss out some. Also, you may come across a particular vulnerability that may or may not be a false positive, to confirm this; a different tool that does a same vulnerability check maybe used to zero-in on that vulnerability. <p>Enter **RapidScan**.
---
### FYI:
- _software is **still under development** and currently supports **25** vulnerability checks._
- _parallel processing not yet implemented, may be coded as more checks gets introduced._

## Tests Fort
- :white_check_mark: DNS/HTTP Load Balancers.
- :white_check_mark: Web Application Firewalls.
- :white_check_mark: Checks for Joomla, WordPress and Drupal
- :white_check_mark: SSL Vulnerabilities (_HEARTBLEED, FREAK, POODLE, CCS Injection, LOGJAM_).
- :white_check_mark: Commonly Opened Ports.
- :white_check_mark: DNS Zone Transfers using multiple tools (_Fierce, DNSWalk, DNSRecon_).
- :white_check_mark: Robots.txt and Sitemap Availability.
- & more coming up...

## Requirements
- Kali Linux 2.0 or Rolling Distro. (_The latest, the better the tool performs._)

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

![output of rapidscan](https://github.com/skavngr/rapidscan/blob/master/splashscreen_rapidscan.PNG)

## Contribution
- https://gist.github.com/MarcDiethelm/7303312

