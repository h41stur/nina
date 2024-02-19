import dns.resolver
import dns.zone
import asyncio
import socket
from typing import List
from prettytable import PrettyTable
from nina.lib.colors import *

class ZoneTransfer:
    def __init__(self, domain, store, report_path, vulnerability):
        self.domain = domain
        self.store = store
        self.report_path = report_path
        self.vulnerability = vulnerability
        self.hosts: List[str] = list()
        self.ns: List[str] = list()
        self.ns_vuln: List[str] = list()

    async def zone_transfer(self) -> None:
        running_message("Starting domain zone transfer attack...\n")
        asyncio.sleep(0.2)

        # iterating through name servers to attack everyone
        try:
            name_servers = dns.resolver.resolve(self.domain, 'NS')
            for n in name_servers:
                ip = dns.resolver.resolve(n.target, 'A')
                self.ns.append(str(n))
                for i in ip:
                    try:
                        zone = dns.zone.from_xfr(dns.query.xfr(str(i), self.domain))
                        for h in zone:
                            self.hosts.append(h)
                        if zone:
                            self.ns_vuln.append(n)
                    except:
                        print(f"[{YELLOW}!{RESET}] NS {n} {RED}refused zone transfer!")
                        continue
        except:
            warning_message("Unable to try zone transfer")

        if self.ns_vuln:
            for i in self.ns_vuln:
                self.vulnerability.append(f"Infra, DNS Zone Transfer, Certain, [5.3](https://www.first.org/cvss/calculator/3.1#CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N), Name Server: {i}")

        # open file to write
        if self.hosts:
            table = PrettyTable(["ZONE TRANSFER", "IP"])
            if self.store:
                f = open(self.report_path, "a")
                f.write(f"\n\n## Zone transfer from {self.domain}\n\n")
                f.write(f"The domain {self.domain} has {len(self.ns)} Name Servers:\n\n")
                f.write("| Name Servers |\n|--------------|\n")
                for n in self.ns:
                    f.write(f"| {n} |\n")
                f.write("\n\n")
                f.write("|" + " ZONE TRANSFER \t\t\t\t| IP \t\t\t|\n" + "|" + "-" * 47 + "|" + "-" * 23 + "|\n")


                for i in self.hosts:
                    if '@' not in i:
                        s = str(i) + "." + self.domain
                        try:
                            ip = socket.gethostbyname(s)
                        except:
                            ip = "Not found!"

                        f.write(f"| {s} | {ip} |\n")
                        table.add_row([s, ip])
                        table.align["ZONE TRANSFER"] = "l"
                f.close()

            for i in self.hosts:
                if '@' not in i:
                    s = str(i) + "." + self.domain
                    try:
                        ip = socket.gethostbyname(s)
                    except:
                        ip = "Not found!"

                    table.add_row([s, ip])
                    table.align["ZONE TRANSFER"] = "l"


            print(table)


