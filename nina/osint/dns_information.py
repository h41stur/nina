import asyncio
import dns.resolver
import wget
from typing import List
from prettytable import PrettyTable
from nina.lib.colors import *

class DNSInformation:
    def __init__(self, domain, store, dir_file, report_path, vulnerability):
        self.domain = domain
        self.store = store
        self.dir_file = dir_file
        self.report_path = report_path
        self.vulnerability = vulnerability


    async def whois_lookup(self) -> None:
        running_message("Performing WHOIS Lookup...\n")
        import whois
        asyncio.sleep(2)
        lookup: List[str] = list()

        try:
            w = whois.whois(self.domain)
        except:
            w = whois.query(self.domain)

        try:
            for i in w:
                if i not in lookup:
                    lookup.append(f"{i}~{w[i]}")
        except Exception as e:
            error_message(f"An error has ocurred or unable to whois {self.domain}")

        if lookup:
            if self.store:
                f = open(self.report_path, "a")
                f.write(f"\n\n## Whois lookup from {self.domain}\n\n")
                f.write("|" + " KEY \t\t\t\t| VALUE \t\t\t|\n" + "|" + "-" * 47 + "|" + "-" * 23 + "|\n")

            table = PrettyTable(["KEY", "VALUE"])
            for i in lookup:
                s = i.split("~")[0]
                v = i.split("~")[1]
                table.add_row([s, v])
                table.align = "l"
                if self.store:
                    f.write(f"| {s} | {v} |\n")

            print(table)
            if self.store:
                f.close()

    async def dns_information(self) -> None:
        running_message(f"Discovering some DNS information from {self.domain}...\n")
        asyncio.sleep(0.2)
        registry: List[str] = list()
        mail = ""
        txt = ""
        ns = ""

        try:
            mail = dns.resolver.resolve(self.domain, 'MX')
        except:
            pass
        if mail:
            ok_message("Mail Servers:")
            for s in mail:
                registry.append(f"Mail Server,{str(s).split(' ')[1]}")
                print(f"\t {GREEN}-{RESET} {str(s).split(' ')[1]}")

        try:
            txt = dns.resolver.resolve(self.domain, 'TXT')
        except:
            pass
        if txt:
            reg: List[str] = list()
            ok_message("TXT Records:")
            for i in txt:
                i = i.to_text()
                registry.append(f"TXT Records,{i}")
                if "?all" in i or "~all" in i or "spf" in i and "all" not in i:
                    reg = i
                print(f"\t {GREEN}-{RESET} {i}")

            if reg:
                warning_message(f"{YELLOW}Possible e-mail spoofing vulnerability in TXT record:{RESET} {reg}")
                self.vulnerability.append(
                    f"Infra, E-mail Spoofing, Possible, [9.1](https://www.first.org/cvss/calculator/3.1#CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N), TXT Record: {reg}"
                )

        try:
            ns = dns.resolver.resolve(self.domain, 'NS')
        except:
            pass
        if ns:
            ok_message("Name Servers:")
            for n in ns:
                registry.append(f"Name Server,{str(n)}")
                print(f"\t {GREEN}-{RESET} {str(n)}")

        if mail or txt or ns:
            if self.store:
                f = open(self.report_path, "a")
                f.write(f"\n\n## DNS information from {self.domain}\n\n")
                f.write("|" + " KEY \t\t\t\t| VALUE \t\t\t|\n" + "|" + "-" * 47 + "|" + "-" * 23 + "|\n")

                for i in registry:
                    i = i.split(",")
                    f.write(f"|{i[0]}|{i[1]}|\n")

                file = ""
                try:
                    filename = self.dir_file + "/" + "dnsmap.png"
                    url = 'https://dnsdumpster.com/static/map/{}.png'.format(self.domain)
                    def bar_progress(current, total, width=80):
                        pass
                    file = wget.download(url, out=filename, bar=bar_progress)
                except Exception as e:
                    print(e)
                    pass


                if file:
                    f.write(f"\n\n### DNS map from {self.domain}\n\n")
                    f.write(f"![DNS map](./dnsmap.png)")

                f.close()










