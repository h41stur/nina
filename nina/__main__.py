import sys
import argparse
import tldextract
import socket
from pathlib import Path
from nina.lib.colors import *
from nina.lib.core import Core
from typing import List
from nina.discovery import (
    portscan,
    js_links,
    search_backups,
    enum_tech,
    detect_waf,
)
from nina.osint import (
    subdomains,
    dns_information,
    dorks,
    find_repos,
    ssl_information,
    github,
    hunter,
    intelx,
)
from nina.vulns import (
    email_spoof,
    zone_transfer,
    subdomain_takeover,
    cors,
)

# threading
try:
    import concurrent.futures
except ImportError:
    warning_message("Nina needs python 3.4 > ro run!")
    sys.exit(1)

def validDomain(domain):
    try:
        h = socket.gethostbyname(domain)
    except:
        warning_message(f"The domain doesn't respond!")
        sys.exit(1)

def write_vulns(vulnerability, store, report_path):

    # print vulnerabilities
    if vulnerability:
        web: List[str] = list()
        infra: List[str] = list()
        if store:
            f = open(report_path, "a")
            f.write(f"\n\n## Vulnerabilities found\n")
            for i in vulnerability:
                i = i.split(",")
                if "WEB" in i[0]:
                    web.append(i)
                if "Infra" in i[0]:
                    infra.append(i)

            if infra:
                f.write(f"\n\n### Infra\n\n")
                f.write("| Vulnerability \t\t\t| Confidence \t\t\t| Endpoint \t\t\t| Severity \t\t\t|\n")
                f.write("|" + "-"*47 + "|" + "-"*47 + "|" + "-"*47 + "|" + "-"*47 + "|\n")

                for i in infra:
                    f.write(f"| {i[1]} | {i[2]} | {i[4]} | {i[3]} |\n")

            if web:
                f.write(f"\n\n### WEB\n\n")
                f.write("| Vulnerability \t\t\t| Confidence \t\t\t| Endpoint \t\t\t| Severity \t\t\t|\n")
                f.write("|" + "-"*47 + "|" + "-"*47 + "|" + "-"*47 + "|" + "-"*47 + "|\n")

                for i in web:
                    f.write(f"| {i[1]} | {i[2]} | {i[4]} | {i[3]} |\n")
            f.close()

    if store:
        print(f"\n\n[{GREEN}+{RESET}] Report saved on {GREEN}{report_path}")

async def start():
    # Program
    parser = argparse.ArgumentParser(
        description="Nina Recon Tool"
    )
    discovery = parser.add_argument_group("Discovery")
    osint = parser.add_argument_group("OSINT")
    vulns = parser.add_argument_group("Vulns")

    parser.add_argument(
        "-d", "--domain", help="Domain to start recon", required=False
    )
    parser.add_argument(
        "-o", "--output", help="Save a directory containing Markdown file with recon report.",
        required=False, action='store_true'
    )
    # parser.add_argument(
    #     "-pr", "--proxy", help="Use a proxy for requests, example: http://127.0.0.1:8080",
    #     required=False, action='store_true'
    # )
    parser.add_argument(
        "-A", "--all", help="Permorm all options at once, except -s and -o (which can be added manually)",
        required=False, action='store_true'
    )
    parser.add_argument(
        "-l", "--limit", help="Limit the number of search results, (default 500).", default=500, type=int
    )
    parser.add_argument(
        "--threads", help="Threads (default 5)", type=int, default=5
    )
    parser.add_argument(
        "-V", "--version", help="Show the version", required=False, action='store_true'
    )
    discovery.add_argument(
        "-p", "--portscan",
        help="Simple portscan and banner grabbing on top 100 ports (makes a huge noise on the network).",
        action='store_true', required=False
    )
    discovery.add_argument(
        "-js", "--js-links", help="Try do find endpoints and parameters in JavaScript files.",
        required=False, action='store_true'
    )
    discovery.add_argument(
        "-t", "--tech", help="Try to discover technologies in the page", required=False,
        action='store_true'
    )
    discovery.add_argument(
        "-b", "--backups",
        help="Try to find some commom backup files in the page. This option works better with -s enabled.",
        required=False, action='store_true'
    )
    discovery.add_argument(
        "-w", "--waf", help="Try to detect WAF on the page.", required=False, action='store_true'
    )
    osint.add_argument(
        "-gh", "--github",
        help="Search for GitHub codes (GitHub API Key required)", required=False, action='store_true'
    )
    osint.add_argument(
        "--hunter",
        help="Search for emails on hunter.io (Hunter.io API Key required)", required=False, action='store_true'
    )
    osint.add_argument(
        "--intelx",
        help="Search informations on intelx.io (IntelX API Key required)", required=False, action='store_true'
    )
    osint.add_argument(
        "--whois", help="Perform a Whois lookup.", required=False, action='store_true'
    )
    osint.add_argument(
        "-D", "--dns", help="Look for some DNS information", required=False, action='store_true'
    )
    osint.add_argument(
        "--dork", help="Try some Google dorks", action='store_true', required=False
    )
    osint.add_argument(
        "-s", "--subdomains", help="Do a search for any subdomain registered", required=False,
        action='store_true'
    )
    osint.add_argument(
        "--ssl", help="Extract information from SSL Certificate.", required=False, action='store_true'
    )
    osint.add_argument(
        "-r", "--repos",
        help="Try to discover valid repositories of the domain. This option works better with -s enabled.",
        action='store_true', required=False
    )
    vulns.add_argument(
        "--spoof", help="Check if domain can be spoofed based on SPF and DMARC records", required=False,
        action='store_true'
    )
    vulns.add_argument(
        "-a", "--axfr", help="Try a domain zone transfer attack", required=False, action='store_true'
    )
    vulns.add_argument(
        "--subtake", help="Check for subdomain takeover vulnerability", required=False, action='store_true'
    )
    vulns.add_argument(
        "-c", "--cors", help="Try to find CORS misconfigurations", required=False, action='store_true'
    )


    args = parser.parse_args()


    ## VARIABLES
    THREADS: int = args.threads
    # MAX_EMAILS = args.email
    DIR = Path(__file__).parent
    DATA_DIR = DIR / "data"
    limit: int = args.limit
    version = "3.0"
    vulnerability: List[str] = list()

    # show version
    if args.version:
        print(f"\nNina Recon Tool version: {version}")
        sys.exit(1)

    # working with domain
    if not args.domain:
        error_message("error: the following arguments are required: -d/--domain or -h/--help")
        sys.exit(1)
    else:
        domain = args.domain
        url_original = domain

    # Cleaning domain input
    if "." not in domain:
        error_message("Invalid domain format, please inform in format: example.com")
        sys.exit(1)
    extracted = tldextract.extract(domain)
    corp = extracted.domain
    domain = f"{extracted.domain}.{extracted.suffix}"
    validDomain(domain)

    # check if --ouput is passed
    report_path = ""
    if args.output:
        store = 1
        dir_file = str(os.getcwd()) + "/" + domain
        try:
            os.mkdir(dir_file)
        except FileExistsError:
            warning_message(f"The directory {dir_file} already exists!")
            # sys.exit(0)
        report_path = dir_file + "/" + domain + ".report.md"
        if os.path.isfile(report_path):
            os.remove(report_path)
            with open(report_path, "w") as f:
                f.write(f"# NINA RECON TOOL REPORT FROM {domain.upper()}\n\n")
                f.close()
    else:
        store = 0
        dir_file = ''

    # start scan full
    if args.all:
        subs: List[str] = list()
        subt: List[str] = list()
        if args.subdomains:
            subs = await subdomains.SearchSubdomains(domain, store, report_path).process()
            subt = subs
        try:
            await dns_information.DNSInformation(domain, store, dir_file, report_path, vulnerability).whois_lookup()
            await dns_information.DNSInformation(domain, store, dir_file, report_path, vulnerability).dns_information()
            await email_spoof.Spoof(domain, vulnerability).spoof()
            await zone_transfer.ZoneTransfer(domain, store, report_path, vulnerability).zone_transfer()
            await portscan.PortScan(domain, store, report_path, subs, THREADS).portscan()
            if subt:
                subdomain_takeover.SubTake(domain, store, subs, report_path, THREADS).sub_take()
            await ssl_information.SSLInformation(domain, store, DATA_DIR, report_path, subs, THREADS).ssl_information()
            js_links.JSLinks(domain, store, report_path, subs, THREADS).js_links()
            await cors.Cors(domain, store, report_path, subs, DATA_DIR, vulnerability, THREADS).cors()
            dorks.Dorks(domain, store, report_path).dorks()
            await search_backups.SearchBkp(domain, store, report_path, subs, THREADS).search_backups()
            await enum_tech.EnunTech(domain, store, report_path, subs, THREADS).tech()
            await find_repos.FindRepos(domain, store, report_path, subs).find_repos()
            await detect_waf.DetectWaf(domain, store, report_path, subs, DATA_DIR, THREADS).detect_waf()
            await github.SearchGithub(corp, limit, DATA_DIR, store, report_path).search()
            await hunter.SearchHunter(domain, limit, DATA_DIR, store, report_path).search()
            await intelx.SearchIntelx(domain, DATA_DIR, store, report_path).search()
            write_vulns(vulnerability, store, report_path)
            sys.exit(1)

        except KeyboardInterrupt:
            warning_message("Interrupt handler received, exiting...\n")
            sys.exit(1)

    # start scan single option
    subs: List[str] = list()
    try:
        # DNS information
        if args.dns:
            await dns_information.DNSInformation(domain, store, dir_file, report_path, vulnerability).dns_information()
        # subdomain enumeration
        if args.subdomains:
            subs = await subdomains.SearchSubdomains(domain, store, report_path).process()
        # subdomain takeover
        if args.subtake:
            if not subs:
                subs = await subdomains.SearchSubdomains(domain, store, report_path).process()
            subdomain_takeover.SubTake(domain, store, subs, report_path, THREADS).sub_take()
        # Zone transfer attack
        if args.axfr:
            await zone_transfer.ZoneTransfer(domain, store, report_path, vulnerability).zone_transfer()
        # find repos
        if args.repos:
            await find_repos.FindRepos(domain, store, report_path, subs).find_repos()
        # detect WAF
        if args.waf:
            await detect_waf.DetectWaf(domain, store, report_path, subs, DATA_DIR, THREADS).detect_waf()
        # Perform whois lookup
        if args.whois:
            await dns_information.DNSInformation(domain, store, dir_file, report_path, vulnerability).whois_lookup()
        # search for backups
        if args.backups:
            await search_backups.SearchBkp(domain, store, report_path, subs, THREADS).search_backups()
        # discover technologies
        if args.tech:
            await enum_tech.EnunTech(domain, store, report_path, subs, THREADS).tech()
        # HUNT!
        # if parsing.hunt:
        #     hunt(domain, store, reportPath, subs, srcPath, vulnerability, THREADS, url_original)
        # CORS misconfiguration
        if args.cors:
            await cors.Cors(domain, store, report_path, subs, DATA_DIR, vulnerability, THREADS).cors()
        # DORKS
        if args.dork:
            dorks.Dorks(domain, store, report_path).dorks()
        # Portscan
        if args.portscan:
            await portscan.PortScan(domain, store, report_path, subs, THREADS).portscan()
        # E-mail spoof
        if args.spoof:
            await email_spoof.Spoof(domain, vulnerability).spoof()
        # Find emails
        # if args.email:
        #     find_emails(domain, store, reportPath, MAX_EMAILS, THREADS)
        # SSL certificate information
        if args.ssl:
            await ssl_information.SSLInformation(domain, store, DATA_DIR, report_path, subs, THREADS).ssl_information()
        # JS links
        if args.js_links:
            js_links.JSLinks(domain, store, report_path, subs, THREADS).js_links()
        # GitHub mentions
        if args.github:
            await github.SearchGithub(corp, limit, DATA_DIR, store, report_path).search()
        # Hunter.io search
        if args.hunter:
            await hunter.SearchHunter(domain, limit, DATA_DIR, store, report_path).search()
        # IntelX search
        if args.intelx:
            await intelx.SearchIntelx(domain, DATA_DIR, store, report_path).search()
    except KeyboardInterrupt:
        warning_message("Interrupt handler received, exiting...\n")
        exit(1)

    write_vulns(vulnerability, store, report_path)



async def initial() -> None:
    try:
        Core.banner()
        await start()
    except KeyboardInterrupt:
        warning_message("ctrl+c detected from user, quitting.")
    except Exception as er:
        print(er)
        sys.exit(1)