import asyncio
import dns.resolver
import socket
import re
from typing import List
from nina.lib.colors import *

class Spoof:
    def __init__(self, domain, vulnerability):
        self.domain = domain
        self.vulnerability = vulnerability
        self.spoofable = False
        self.dns_server = ""
        self.spf = None
        self.spf_rec = None
        self.dmarc_rec = ""

    async def spoof(self) -> None:
        running_message("hecking SPF and DMARC records...\n")
        asyncio.sleep(0.2)

        dns_resolver = dns.resolver.Resolver()
        # get DNS Server
        dns_resolver.nameservers = ['1.1.1.1']
        query = dns_resolver.resolve(self.domain, 'SOA')
        if query:
            for d in query:
                d = socket.gethostbyname(str(d.mname))
                dns_resolver.nameservers[0] = d
        else:
            dns_resolver.nameservers[0] = '1.1.1.1'

        # get SPF Record
        try:
            self.spf = dns_resolver.resolve(self.domain, 'TXT')
        except dns.resolver.NoAnswer:
            warning_message("No TXT record found!")
            return
        except:
            dns_resolver.nameservers[0] = '1.1.1.1'
            self.spf = dns_resolver.resolve(self.domain, 'TXT')

        for d in self.spf:
            if 'spf1' in str(d):
                self.spf_rec = str(d).replace('"', "")
                break
        # get ALL property
        if self.spf_rec:
            n = self.spf_rec.count("~all") + self.spf_rec.count(" ?all") + self.spf_rec.count(" -all")
            if n == 1:
                spf_all = re.search("[-,~,?]all", self.spf_rec).group(0)
            elif n == 0:
                spf_all = None
            else:
                spf_all = "many"

            # get SPF includes
            includes: List[str] = list()
            n = len(re.compile("[ ,+]a[ , :]").findall(self.spf_rec))
            n += len(re.compile("[ ,+]mx[ ,:]").findall(self.spf_rec))
            n += len(re.compile("[ ]ptr[ ]").findall(self.spf_rec))
            n += len(re.compile("exists[:]").findall(self.spf_rec))
            for i in range(0, n):
                includes.append("nina")
            for i in self.spf_rec.split(" "):
                item = i.replace("include:", "")
                if "include:" in i:
                    includes.append(item)
            spf_includes = len(includes)
        else:
            warning_message("No SPF record found!")

        # get DMARC record
        try:
            try:
                dmarc = dns_resolver.resolve(f"_dmarc.{self.domain}", 'TXT')
            except:
                dns_resolver.nameservers[0] = '1.1.1.1'
                dmarc = dns_resolver.resolve(f"_dmarc.{self.domain}", 'TXT')
            for d in dmarc:
                if "DMARC" in str(d):
                    self.dmarc_rec = str(d).replace('"', "")
                    break
        except:
            warning_message("No DMARC record found!.")

        # get DMARC Properties
        p = None
        aspf = None
        sp = None
        pct = None
        if self.dmarc_rec:
            # get policy
            if "p=" in self.dmarc_rec:
                p = self.dmarc_rec.split("p=")[1].split(";")[0]
            # get aspf
            if "aspf=" in self.dmarc_rec:
                aspf = self.dmarc_rec.split("aspf=")[1].split(";")[0]
            # get sp
            if "sp=" in self.dmarc_rec:
                sp = self.dmarc_rec.split("sp=")[1].split(";")[0]
            # get pct
            if "pct=" in self.dmarc_rec:
                pct = self.dmarc_rec.split("pct=")[1].split(";")[0]

        # check spoof
        try:
            if pct and int(pct) != 100:
                self.spoofable = True
                ok_message(f"Possible spoofing for {self.domain}\n")
                print(
                    f"\t{GREEN}- Reason{RESET}: The pct tag (percentage) is lower than 100%, DMARC record has instructed the receiving server to reject {pct}% of email that fails DMARC authentication and to send a report about it to the mailto: address in the record.")
            elif self.spf_rec is None:
                if p is None:
                    self.spoofable = True
                    ok_message(f"Possible spoofing for {self.domain}\n")
                    print(f"\t{GREEN}- Reason{RESET}: Domain has no SPF record or DMARC tag \"p\" (policy).")
            elif spf_includes > 10 and p is None:
                self.spoofable = True
                ok_message(f"Possible spoofing for {self.domain}\n")
                print(f"\t{GREEN}- Reason{RESET}: Too many include records without DMARC policy can override each other")
            elif spf_all == "many":
                if p is None:
                    self.spoofable = True
                    ok_message(f"Possible spoofing for{self.domain}\n")
                    print(f"\t{GREEN}- Reason{RESET}: More than one record \"all\" with no DMARC \"p\" tag (policy).")
            elif spf_all and p is None:
                self.spoofable = True
                ok_message(f"Possible spoofing for {self.domain}\n")
                print(f"\t{GREEN}- Reason{RESET}: DMARC without \"p\" tag (policy)")
            elif spf_all == "-all":
                if p and aspf and sp == "none":
                    self.spoofable = True
                    ok_message(f"Possible subdomain spoofing for {self.domain}\n")
                    print(
                        f"\t{GREEN}- Reason{RESET}: SPF with hardfail (-all), but DMARC without \"sp\" tag (subdomain policy)")
                elif aspf is None and sp == "none":
                    self.spoofable = True
                    ok_message(f"Possible subdomain spoofing for {self.domain}\n")
                    print(
                        f"\t{GREEN}- Reason{RESET}: SPF with hardfail (-all), but DMARC \"sp\" tag (subdomain policy) is \"none\" and \"aspf\" tag (SPF aligment) missing.")
                elif p == "none" and (aspf == "r" or aspf is None) and sp is None:
                    self.spoofable = True
                    ok_message(f"Possible Mailbox dependant spoofing for {self.domain}\n")
                    print(
                        f"\t{GREEN}- Reason{RESET}: SPF with hardfail (-all), but DMARC \"aspf\" tag (SPF aligment) is \"r\" (relaxed) or missing, \"p\" tag (policy) and \"sp\" tag (subdomain policy) missing.")
                elif p == "none" and aspf == "r" and (sp == "reject" or sp == "quarentine"):
                    self.spoofable = True
                    ok_message(f"Possible Organizational spoofing for {self.domain}\n")
                    print(
                        f"\t{GREEN}- Reason{RESET}: SPF with hardfail (-all), but DMARC \"aspf\" tag (SPF aligment) is \"r\" (relaxed), \"p\" tag (policy) is \"none\" and \"sp\" tag (subdomain policy) is \"reject\" or \"quarentine\". This allows for spoofing within the organization.")
                elif p == "none" and aspf is None and (sp == "reject" or sp == "quarentine"):
                    self.spoofable = True
                    ok_message(f"Possible Organizational spoofing for {self.domain}\n")
                    print(
                        f"\t{GREEN}- Reason{RESET}: SPF with hardfail (-all), but DMARC \"aspf\" tag (SPF aligment) is missing and \"sp\" tag (subdomain policy) is \"reject\" or \"quarentine\". This allows for spoofing within the organization.")
                elif p == "none" and aspf is None and sp == "none":
                    self.spoofable = True
                    ok_message(f"Possible subdomain spoofing for {self.domain}\n")
                    print(
                        f"\t{GREEN}- Reason{RESET}: SPF with hardfail (-all), but DMARC \"p\" tag (policy) and \"sp\" tag (subdomain policy) is \"none\", and \"aspf\" tag (SPF aligment) is missing.")
                else:
                    warning_message(f"Spoofing not possible for {self.domain}")
            elif spf_all == "~all":
                if p == "none" and sp == "reject" or sp == "quarentine":
                    self.spoofable = True
                    ok_message(f"Possible Organizational subdomain spoofing for {self.domain}\n")
                    print(
                        f"\t{GREEN}- Reason{RESET}: SPF with softfail (~all), but DMARC \"p\" tag (policy) is \"none\" and \"sp\" tag (subdomain policy) is \"reject\" or \"quarentine\". This allows for spoofing within the organization.")
                elif p == "none" and sp is None:
                    self.spoofable = True
                    ok_message(f"Possible spoofing for {self.domain}\n")
                    print(
                        f"\t{GREEN}- Reason{RESET}: SPF with softfail (~all), but DMARC \"p\" tag (policy) is \"none\" and \"sp\" tag (subdomain policy) is missing.")
                elif p == "none" and sp == "none":
                    self.spoofable = True
                    ok_message(f"Possible Organizational subdomain spoofing for {self.domain}\n")
                    print(
                        f"\t{GREEN}- Reason{RESET}: SPF with softfail (~all), but DMARC \"p\" tag (policy) and \"sp\" tag (subdomain policy) is \"none\". This allows for spoofing within the organization.")
                elif (p == "reject" or p == "quarentine") and aspf is None and sp == "none":
                    self.spoofable = True
                    ok_message(f"Possible subdomain spoofing for {self.domain}\n")
                    print(
                        f"\t{GREEN}- Reason{RESET}: SPF with softfail (~all), but DMARC p tag (policy) is reject or quarentine, aspf tag (SPF aligment) is missing and sp tag (subdomain policy) is none.")
                elif (p == "reject" or p == "quarentine") and aspf and sp == "none":
                    self.spoofable = True
                    ok_message(f"Possible subdomain spoofing for {self.domain}\n")
                    print(
                        f"\t{GREEN}- Reason{RESET}: SPF with softfail (~all), but DMARC \"p\" tag (policy) is \"reject\" or \"quarentine\", \"aspf\" tag (SPF aligment) exists, but \"sp\" tag (subdomain policy) is \"none\".")
                else:
                    warning_message(f"Spoofing not possible for {self.domain}")
            elif spf_all == "?all":
                if (p == "reject" or p == "quarentine") and aspf and sp == "none":
                    self.spoofable = True
                    ok_message(f"Possible subdomain Mailbox dependant spoofing for {self.domain}\n")
                    print(
                        f"\t{GREEN}- Reason{RESET}: SPF neutral (?all), but DMARC \"p\" tag (policy) is \"reject\" or \"quarentine\", \"aspf\" tag (SPF aligment) exists, but \"sp\" tag (subdomain policy) is \"none\".")
                elif (p == "reject" or p == "quarentine") and aspf is None and sp == "none":
                    self.spoofable = True
                    ok_message(f"Possible subdomain Mailbox dependant spoofing for {self.domain}\n")
                    print(
                        f"\t{GREEN}- Reason{RESET}: SPF neutral (?all), but DMARC \"p\" tag (policy) is \"reject\" or \"quarentine\", \"aspf\" tag (SPF aligment) is missing, but \"sp\" tag (subdomain policy) is \"none\".")
                elif p == "none" and aspf == "r" and sp is None:
                    self.spoofable = True
                    ok_message(f"Possible spoofing for {self.domain}\n")
                    print(
                        f"\t{GREEN}- Reason{RESET}: SPF neutral (?all), but DMARC \"p\" tag (policy) is \"none\", \"aspf\" tag (SPF aligment) is \"r\" (relaxed) and \"sp\" tag (subdomain policy) is missing.")
                elif p == "none" and aspf == "r" and sp == "none":
                    self.spoofable = True
                    ok_message(f"Possible subdomain or organizational spoofing for {self.domain}\n")
                    print(
                        f"\t{GREEN}- Reason{RESET}: SPF neutral (?all), but DMARC \"p\" tag (policy) is \"none\", \"aspf\" tag (SPF aligment) is \"r\" (relaxed) and \"sp\" tag (subdomain policy) is \"none\".")
                elif p == "none" and aspf == "s" or None and sp == "none":
                    self.spoofable = True
                    ok_message(f"Possible subdomain spoofing for {self.domain}\n")
                    print(
                        f"\t{GREEN}- Reason{RESET}: SPF neutral (?all), but DMARC \"p\" tag (policy) is \"none\", \"aspf\" tag (SPF aligment) is \"s\" (strict) and \"sp\" tag (subdomain policy) is \"none\".")
                elif p == "none" and aspf == "s" or None and sp is None:
                    self.spoofable = True
                    ok_message(f"Possible subdomain Mailbox dependant spoofing for {self.domain}\n")
                    print(
                        f"\t{GREEN}- Reason{RESET}: SPF neutral (?all), but DMARC \"p\" tag (policy) is \"none\", \"aspf\" tag (SPF aligment) is \"s\" (strict) or missing, and \"sp\" tag (subdomain policy) is missing")
                elif p == "none" and aspf and (sp == "reject" or sp == "quarentine"):
                    self.spoofable = True
                    ok_message(f"Possible Organizational subdomain spoofing for {self.domain}\n")
                    print(
                        f"\t{GREEN}- Reason{RESET}: SPF neutral (?all), but DMARC \"p\" tag (policy) \"none\", \"aspf\" tag (SPF aligment) exists, but \"sp\" tag (subdomain policy) is \"reject\" or \"quarentine\". This allows for spoofing within the organization.")
                elif p == "none" and aspf is None and sp == "reject":
                    self.spoofable = True
                    ok_message(f"Possible Organizational subdomain spoofing for {self.domain}\n")
                    print(
                        f"\t{GREEN}- Reason{RESET}: SPF neutral (?all), but DMARC \"p\" tag (policy) \"none\", \"aspf\" tag (SPF aligment) is missing, and \"sp\" tag (subdomain policy) is \"reject\". This allows for spoofing within the organization.")
                else:
                    warning_message(f"Spoofing not possible for {self.domain}")
            else:
                warning_message(f"Spoofing not possible for {self.domain}")
        except:
            warning_message("Unable to check!.")

        if self.spoofable:
            if self.spf_rec:
                print(f"\t{GREEN}- SPF{RESET}: {self.spf_rec}")
            if self.dmarc_rec:
                print(f"\t{GREEN}- DMARC{RESET}: {self.dmarc_rec}")
            vuln = f"Infra, E-mail Spoofing, Possible, [9.1](https://www.first.org/cvss/calculator/3.1#CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N), TXT Record: \"{self.spf_rec}\""
            if not vuln in self.vulnerability:
                self.vulnerability.append(vuln)

