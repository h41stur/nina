# Nina Recon

Nina is a tool disigned to perform basic recon from domains and their subdomains.

This tool was made thinking about saving time in the initial penetration testing / bug bounty phase.

## Installation

```bash
git clone https://github.com/h41stur/nina.git
cd nina
pip3 install -r requirements.txt
```

## Help Panel

```
    NINA RECON TOOL

              .--~~,__
 :-....,-------`~~'._.'
  `-,,,  ,_      ;'~U'
   _,-' ,'`-__; '--.
  (_/'~~      ''''(;

      by H41stur

usage: nina.py [-h] [-d DOMAIN] [-o] [-A] [--whois] [-D] [-a] [--dork] [-s] [--subtake] [-t] [-c] [-b] [-w] [--hunt] [-r] [--threads THREADS] [-V]

Nina Recon Tool

options:
  -h, --help            show this help message and exit
  -d DOMAIN, --domain DOMAIN
                        Domain to start recon
  -o, --output          Save a directory containing Markdown file with recon report.
  -A, --all             Permorm all options at once, except -s and -o (which can be added manually)
  --whois               Perform a Whois lookup.
  -D, --dns             Look for some DNS information
  -a, --axfr            Try a domain zone transfer attack
  --dork                Try some dorks
  -s, --subdomains      Do a search for any subdomain registered
  --subtake             Check for subdomain takeover vulnerability
  -t, --tech            Try to discover technologies in the page
  -c, --cors            Try to find CORS misconfigurations
  -b, --backups         Try to find some commom backup files in the page. This option works better with -s enabled.
  -w, --waf             Try to detect WAF on the page.
  --hunt                Try to find usefull information about exploiting vectors.
  -r, --repos           Try to discover valid repositories of the domain. This option works better with -s enabled.
  --threads THREADS     Threads (default 5)
  -V, --version         Show the version

  ```

  ### 💐💐💐 Tribute to Nina 💐💐💐

  Nina was the sweetest little dog that ever lived. She battled hard with distemper and crossed the rainbow bridge peacefully in my arms.

  She fought the good fight.
