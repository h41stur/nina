# Nina Recon

Nina is a tool disigned to perform basic recon from domains and their subdomains.

This tool was made thinking about saving time in the initial penetration testing / bug bounty phase.

## Installation

```bash
git clone https://github.com/h41stur/nina.git
cd nina
pip3 install -r requirements.txt
```

## Usage

```bash
python3 nina.py -h
```

This will display help for the tool. Here are all the switches it supports.

```
    NINA RECON TOOL

              .--~~,__
 :-....,-------`~~'._.'
  `-,,,  ,_      ;'~U'
   _,-' ,'`-__; '--.
  (_/'~~      ''''(;

      by H41stur

usage: nina.py [-h] [-d DOMAIN] [-o] [-A] [--whois] [-D] [--spoof] [-a] [--dork] [-s] [-p] [--subtake] [--ssl] [-t] [-c] [-b] [-w] [--hunt] [-r] [--email [EMAIL]] [--threads THREADS] [-V]

Nina Recon Tool

options:
  -h, --help            show this help message and exit
  -d DOMAIN, --domain DOMAIN
                        Domain to start recon
  -o, --output          Save a directory containing Markdown file with recon report.
  -A, --all             Permorm all options at once, except -s and -o (which can be added manually)
  --whois               Perform a Whois lookup.
  -D, --dns             Look for some DNS information
  --spoof               Check if domain can be spoofed based on SPF and DMARC records
  -a, --axfr            Try a domain zone transfer attack
  --dork                Try some dorks
  -s, --subdomains      Do a search for any subdomain registered
  -p, --portscan        Simple portscan made on https://hackertarget.com/nmap-online-port-scanner
  --subtake             Check for subdomain takeover vulnerability
  --ssl                 Extract information from SSL Certificate.
  -t, --tech            Try to discover technologies in the page
  -c, --cors            Try to find CORS misconfigurations
  -b, --backups         Try to find some commom backup files in the page. This option works better with -s enabled.
  -w, --waf             Try to detect WAF on the page.
  --hunt                Try to find usefull information about exploiting vectors.
  -r, --repos           Try to discover valid repositories of the domain. This option works better with -s enabled.
  --email [EMAIL]       Try to find some emails from symem.info. Max 50 emails.
  --threads THREADS     Threads (default 5)
  -V, --version         Show the version

  ```

## Features

:heavy_check_mark: Perform a Whois lookup.

:heavy_check_mark: Search for useful DNS information.

:heavy_check_mark: Search for email spoofing vulnerability.

:heavy_check_mark: Domain zone transfer attack.

:heavy_check_mark: Perform Google dorks.

:heavy_check_mark: Search for subdomains.

:heavy_check_mark: Perform portscan.

:heavy_check_mark: Check for subdomain takeover.

:heavy_check_mark: Ennumerate some techs on pages.

:heavy_check_mark: Check for CORS misconfiguration.

:heavy_check_mark: Search for common backup files.

:heavy_check_mark: Try to detect WAF.

:heavy_check_mark: Check for common vulnerabilities, like SQLi, XSS and Open Redirect.

:heavy_check_mark: Search for git repos.

:heavy_check_mark: Search for employees emails.

# 💐💐💐 Tribute to Nina 💐💐💐

Nina was the sweetest little dog that ever lived. She battled hard with distemper and crossed the rainbow bridge peacefully in my arms.

She fought the good fight.
