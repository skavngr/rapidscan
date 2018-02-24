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
> Being a pentester for years, its quite a fuss to run dozens of security scanning tools and there are chances you may miss out some. Unless you are a pro at automating stuff, it is a herculean task to run all tools manually. The ultimate goal of this software is to solve that problem.<p>Enter **RapidScan**.

## Why RapidScan?
- **one-step installation**.
- **executes a multitude of security scanning tools**, does other **custom coded checks** and **prints the results spontaneously**.
- saves a lot of time, **indeed a lot time!**.
- **checks for same vulnerabilities with multiple tools** to help you **zero-in on false positives** effectively.
- **legends** to help you which tests may take longer time, so you can `Ctrl+C` to skip if needed. (_under development_)
- **vulnerability definitions** guides you what the vulnerability actually is and the threat it can pose. (_under development_)
- **remediations** tells you how to plug/fix the found vulnerability. (_under development_)

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
- Kali Linux 2.0 or Rolling Distro. (_the latest the distro, the better the tool performs._)

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

