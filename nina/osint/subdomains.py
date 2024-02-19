import asyncio
import aiohttp
import json
import re
import sys
import socket
import urllib3
import warnings
from typing import List, Tuple
from prettytable import PrettyTable
from nina.lib.colors import *
from nina.lib.core import Core

urllib3.disable_warnings()
warnings.simplefilter("ignore")

class SearchSubdomains:
    def __init__(self, domain, store, report_path) -> None:
        self.domain = domain
        self.store = store
        self.report_path = report_path

    # Consulting crt.sh
    async def crt_search(self, domain: str) -> Tuple[str]:
        url = f"https://crt.sh/?q={domain}&output=json"
        headers = {
            "Host": "crt.sh",
            "User-Agent": Core.user_agent_list(),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"
        }
        try:
            async with aiohttp.ClientSession(headers=headers) as sess:
                async with sess.get(url) as resp:
                    return await resp.text()
        except KeyboardInterrupt:
            warning_message("Interrupt handler received, exiting...\n")
            sys.exit(1)
        except:
            pass

    # Consulting Hackertarget
    async def hackertarget_search(self, domain: str) -> Tuple[str]:
        url = f"https://api.hackertarget.com/hostsearch/?q={domain}#result"
        headers = {
            "Host": "api.hackertarget.com",
            "User-Agent": Core.user_agent_list(),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"
        }
        try:
            async with aiohttp.ClientSession(headers=headers) as sess:
                async with sess.get(url) as resp:
                    return await resp.text()
        except KeyboardInterrupt:
            warning_message("Interrupt handler received, exiting...\n")
            sys.exit(1)
        except:
            pass

    # Consulting AlienVault
    async def alienvault_search(self, domain: str) -> Tuple[str]:
        url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"
        headers = {
            "Host": "otx.alienvault.com",
            "User-Agent": Core.user_agent_list(),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"
        }
        try:
            async with aiohttp.ClientSession(headers=headers) as sess:
                async with sess.get(url) as resp:
                    return await resp.text()
        except KeyboardInterrupt:
            warning_message("Interrupt handler received, exiting...\n")
            sys.exit(1)
        except:
            pass

    # Consulting URLScan
    async def urlscan_search(self, domain: str) -> Tuple[str]:
        url = f"https://urlscan.io/api/v1/search/?q={domain}"
        headers = {
            "Host": "urlscan.io",
            "User-Agent": Core.user_agent_list(),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"
        }
        try:
            async with aiohttp.ClientSession(headers=headers) as sess:
                async with sess.get(url) as resp:
                    return await resp.text()
        except KeyboardInterrupt:
            warning_message("Interrupt handler received, exiting...\n")
            sys.exit(1)
        except:
            pass

    # open file to write
    def write_file(self, sub_dom) -> None:
        f = open(self.report_path, "a")
        f.write(f"\n\n## Subdomains from {self.domain}\n\n")
        f.write("|" + " SUBDOMAINS    \t\t\t\t| IP \t\t\t|\n" + "|" + "-" * 47 + "|" + "-" * 23 + "|\n")

        table = PrettyTable([f"SUBDOMAINS", f"IP"])
        # interact through list and check the lenght
        for s in sub_dom:
            try:
                ip = socket.gethostbyname(s)
            except:
                ip = "Not found!"
            f.write(f"| {s} | {ip} |\n")
            table.add_row([s, ip])
            table.align["SUBDOMAINS"] = "l"

        print(table)
        print(f"\n{BLUE}Total discovered sudomains: {GREEN}" + str(len(sub_dom)) + RESET)
        f.write("\n\n**Total discovered sudomains: " + str(len(sub_dom)) + "**")
        f.close()




    # Subdomain discovery function
    async def process(self) -> List[str]:
        running_message(f"Discovering subdomains from {self.domain}...\n")
        asyncio.sleep(0.1)
        sub_dom: List[str] = list()

        crt_response = await self.crt_search(self.domain)
        file = json.dumps(json.loads(crt_response), indent=4)
        sub_domains = sorted(set(re.findall(r'"common_name": "(.*?)"', file)))
        if sub_domains:
            for sub in sub_domains:
                if sub.endswith(self.domain) and sub not in sub_dom:
                    sub_dom.append(sub)

        hackertarget_search = await self.hackertarget_search(self.domain)
        sub_domains = re.findall(f'(.*?),', hackertarget_search)
        if sub_domains:
            for sub in sub_domains:
                if sub.endswith(self.domain) and sub not in sub_dom:
                    sub_dom.append(sub)

        alienvault_search = await self.alienvault_search(self.domain)
        sub_domains = sorted(set(re.findall(r'"hostname": "(.*?)"', alienvault_search)))
        if sub_domains:
            for sub in sub_domains:
                if sub.endswith(self.domain) and sub not in sub_dom:
                    sub_dom.append(sub)

        urlscan_search = await self.urlscan_search(self.domain)
        sub_domains = sorted(set(re.findall(r'https://(.*?).' + self.domain, urlscan_search)))
        if sub_domains:
            for sub in sub_domains:
                if sub.endswith(self.domain) and sub not in sub_dom:
                    sub_dom.append(sub)

        table = PrettyTable([f"SUBDOMAINS", f"IP"])
        for s in sub_dom:
            try:
                ip = socket.gethostbyname(s)
            except:
                ip = "Not found!"
            table.add_row([s, ip])
            table.align["SUBDOMAINS"] = "l"

        print(table)

        if self.store:
            self.write_file(sub_dom)

        return sub_dom

