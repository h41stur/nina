import json
import sys
import asyncio
from typing import Union, List
from nina.lib.colors import *

# threading
try:
    import concurrent.futures
except ImportError:
    warning_message("Nina needs python 3.4 > ro run!")
    sys.exit()

class EnunTech:
    def __init__(self, domain, store, report_path, subs, THREADS):
        self.domain = domain
        self.store = store
        self.report_path = report_path
        self.subs = subs
        self.THREADS = THREADS
        self.schemas = ["https://", "http://"]

    async def request_tech(self, subdomain: str) -> Union[List[str], None]:
        techs: List[str] = list()

        try:
            from Wappalyzer import Wappalyzer, WebPage
            wapp = Wappalyzer.latest()
            for schema in self.schemas:
                web = WebPage.new_from_url(f"{schema}{subdomain}", verify=False)
                tech = wapp.analyze_with_versions(web)

                if tech != "{}":
                    file = json.loads(json.dumps(tech, sort_keys=True, indent=4))
                    print(f"[{GREEN}+{RESET}] {schema}{subdomain}")
                    for i in file:
                        try:
                            version = file[i]['versions'][0]
                        except:
                            version = "Version not found!"
                        if f"{subdomain},{i},{version}" not in techs:
                            techs.append(f"{subdomain},{i},{version}")
                        print(f"\t{GREEN}-{RESET} {i}: {version}")
                    print("\n")
                else:
                    warning_message("No common technologies found")
        except Exception as e:
            print(f"[{RED}-{RESET}] An error has ocurred or unable to enumerate {subdomain}")

        if techs:
            return techs
        else:
            return None

    async def tech(self) -> None:
        running_message("Searching for technologies...\n")
        asyncio.sleep(0.2)
        if self.domain not in self.subs:
            self.subs.append(self.domain)

        techs_web: List[str] = list()

        pool = concurrent.futures.ThreadPoolExecutor(max_workers=self.THREADS)
        data = (pool.submit(self.request_tech, s) for s in self.subs)
        for resp in concurrent.futures.as_completed(data):
            resp = await resp.result()
            if resp is not None and resp not in techs_web:
                techs_web.append(resp)

        if techs_web:
            if self.store:
                f = open(self.report_path, "a")
                f.write(f"\n\n## Common technologies found\n\n")
                f.write(
                    "|" + " URL \t\t\t\t| TECHNOLOGY \t\t\t| VERSION \t\t\t|\n" + "|" + "-" * 47 + "|" + "-" * 23 + "|" + "-" * 23 + "|\n")
                for tech in techs_web:
                    for i in tech:
                        i = i.split(",")
                        u = i[0]
                        t = i[1]
                        v = i[2]
                        f.write(f"| {u} | {t} | {v} |\n")
                f.close()

