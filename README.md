[![GitHub issues](https://img.shields.io/github/issues/skavngr/rapidscan.svg?color=%23ff0000)](https://github.com/skavngr/rapidscan/issues)
[![GitHub issues](https://img.shields.io/github/issues-closed/skavngr/rapidscan.svg?color=%2300cc00)](https://github.com/skavngr/rapidscan/issues)
[![GitHub forks](https://img.shields.io/github/forks/skavngr/rapidscan.svg?color=%23ffff00)](https://github.com/skavngr/rapidscan/network)
[![GitHub stars](https://img.shields.io/github/stars/skavngr/rapidscan.svg?color=%23ff3300)](https://github.com/skavngr/rapidscan/stargazers)
[![GitHub license](https://img.shields.io/github/license/skavngr/rapidscan.svg?color=%230000ff)](https://github.com/skavngr/rapidscan/blob/master/LICENSE)

# :red_square: RapidScan v1.2 - _The Multi-Tool Web Vulnerability Scanner_
_**RapidScan has been ported to Python3 i.e. v1.2**. The Python2.7 codebase is available on v1.1 releases section. Download and use it if you still haven't upgraded to Python 3. Kindly note that the v1.1 (Python2.7) will not be enhanced further._

## Evolution:
> It is quite a fuss for a pentester to perform _**binge-tool-scanning**_ (_running security scanning tools one after the other_) sans automation. Unless you are a pro at automating stuff, it is a herculean task to perform binge-scan for each and every engagement. The ultimate goal of this program is to solve this problem through automation; viz. **running multiple scanning tools to discover vulnerabilities, effectively judge false-positives, collectively correlate results** and **saves precious time**; all these under one roof.<p>Enter **RapidScan**.

## Features
- **one-step installation**.
- **executes a multitude of security scanning tools**, does other **custom coded checks** and **prints the results spontaneously**.
- some of the tools include `nmap, dnsrecon, wafw00f, uniscan, sslyze, fierce, lbd, theharvester, amass, nikto` etc executes under one entity.
- saves a lot of time, **indeed a lot time!**.
- **checks for same vulnerabilities with multiple tools** to help you **zero-in on false positives** effectively.
- **extremely light-weight and not process intensive.**
- **legends** to help you understand which tests may take longer time, so you can `Ctrl+C` to skip if needed.
- **association with OWASP Top 10 & CWE 25** on the list of vulnerabilities discovered. (_**under development**_)
- **critical, high, medium, low and informational** classification of vulnerabilities.
- **vulnerability definitions** guides you what the vulnerability actually is and the threat it can pose.
- **remediation** tells you how to plug/fix the found vulnerability.
- **executive summary** gives you an overall context of the scan performed with critical, high, low and informational issues discovered.
- **artificial intelligence** to deploy tools automatically depending upon the issues found. for eg; automates the launch of `wpscan` and `plecost` tools when a wordpress installation is found. (_**under development**_)
- **detailed comprehensive report** in a portable document format (*.pdf) with complete details of the scans and tools used. (_**under development**_)
- **on the run metasploit auxilliary modules** to discover more vulnerabilities. (_**under development**_)

---
### FYI:
- _program is still under development, **works** and currently supports **80** vulnerability tests._
- _parallel processing is not yet implemented, may be coded as more tests gets introduced._

## Vulnerability Checks
- :heavy_check_mark: DNS/HTTP Load Balancers & Web Application Firewalls.
- :heavy_check_mark: Checks for Joomla, WordPress and Drupal
- :heavy_check_mark: SSL related Vulnerabilities (_HEARTBLEED, FREAK, POODLE, CCS Injection, LOGJAM, OCSP Stapling_).
- :heavy_check_mark: Commonly Opened Ports.
- :heavy_check_mark: DNS Zone Transfers using multiple tools (_Fierce, DNSWalk, DNSRecon, DNSEnum_).
- :heavy_check_mark: Sub-Domains Brute Forcing (_DNSMap, amass, nikto_)
- :heavy_check_mark: Open Directory/File Brute Forcing.
- :heavy_check_mark: Shallow XSS, SQLi and BSQLi Banners.
- :heavy_check_mark: Slow-Loris DoS Attack, LFI (_Local File Inclusion_), RFI (_Remote File Inclusion_) & RCE (_Remote Code Execution_).
- & more coming up...

## Requirements
- **Python 3**
- Kali OS (_**Preferred**, as it is shipped with almost all the tools_)
- Tested with Parrot & Ubuntu Operating Systems.

## Usage 
 `python3 rapidscan.py example.com`

https://user-images.githubusercontent.com/6489729/138737524-9c4dc567-ec78-40b4-9a7b-8ff52d5dc98b.mp4


## Installation

Alternatively, your can install the `rapidscan` python module with `pip`. This will create a link for `rapidscan` in your PATH. 

```
git clone https://github.com/skavngr/rapidscan.git /opt/
cd /opt/rapidscan
python3 -m pip install .
```

### Docker Support
Under development.

## Contribution
- Create your feature branch: `git checkout -b my-new-feature`
- Commit your changes: `git commit -am 'Add some feature'`
- Push to the branch: `git push origin my-new-feature`
- Submit a pull request.
