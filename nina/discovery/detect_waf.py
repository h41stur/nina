import asyncio
import requests
import json
import re
import sys
from typing import Union, List
from nina.lib.colors import *

# threading
try:
    import concurrent.futures
except ImportError:
    warning_message("Nina needs python 3.4 > ro run!")
    sys.exit()

class DetectWaf:
    def __init__(self, domain, store, report_path, subs, DATA_DIR, THREADS):
        self.domain = domain
        self.store = store
        self.report_path = report_path
        self.subs = subs
        self.DATA_DIR = DATA_DIR
        self.THREADS = THREADS

    def request_waf(self, subdomain) -> Union[str, None]:
        try:
            r = requests.get("https://raw.githubusercontent.com/h41stur/nina/main/nina/data/references_recon.json",
                             verify=False, timeout=10)
            wafSig = json.loads(r.text)
            wafSig = wafSig["WAF"]
        except:
            with open(self.DATA_DIR / "references_recon.json", "r") as file:
                wafSig = json.load(file)
                wafSig = wafSig["WAF"]

        URL = f"https://{subdomain}/../../../../etc/passwd"
        try:
            r = requests.get(URL, verify=False, timeout=10)
            status = str(r.status_code)
            content = r.text
            headers = str(r.headers)
            cookie = str(r.cookies.get_dict())

            if int(status) >= 400:
                wafMatch = [0, None]
                for name, sign in wafSig.items():
                    score = 0
                    contentSign = sign["page"]
                    statusSign = sign["code"]
                    headersSign = sign["headers"]
                    cookieSign = sign["cookie"]
                    if contentSign:
                        if re.search(contentSign, content, re.I):
                            score += 1
                        if statusSign:
                            if re.search(statusSign, status, re.I):
                                score += 0.5
                        if headersSign:
                            if re.search(headersSign, headers, re.I):
                                score += 1
                        if cookieSign:
                            if re.search(cookieSign, cookie, re.I):
                                score += 1
                        if score > wafMatch[0]:
                            del wafMatch[:]
                            wafMatch.extend([score, name])

                    if wafMatch[0] != 0:
                        ok_message(f"WAF {wafMatch[1]} detected on https://{subdomain}")
                        return f"{subdomain},{wafMatch[1]}"
                    else:
                        print(f"[{RED}-{RESET}] WAF not detected on https://{subdomain}")
                        return None
        except KeyboardInterrupt:
            warning_message("Interrupt handler received, exiting...\n")
            sys.exit(1)
        except:
            print(f"[{YELLOW}!{RESET}] URL https://{subdomain} not accessible")
            return None


    async def detect_waf(self) -> None:
        running_message("Detecting WAF...\n")
        asyncio.sleep(0.2)

        if self.domain not in self.subs:
            self.subs.append(self.domain)

        WAF: List[str] = list()

        pool = concurrent.futures.ThreadPoolExecutor(max_workers=self.THREADS)
        data = (pool.submit(self.request_waf, s) for s in self.subs)
        for resp in concurrent.futures.as_completed(data):
            resp = resp.result()
            if resp is not None and resp not in WAF:
                WAF.append(resp)

        if WAF:
            if self.store:
                f = open(self.report_path, "a")
                f.write(f"\n\n## WAFs detected on scope {self.domain}\n\n")
                f.write("|" + " URL \t\t\t\t| WAF \t\t\t|\n" + "|" + "-" * 47 + "|" + "-" * 23 + "|\n")

                for i in WAF:
                    f.write(f"| {i.split(',')[0]} | {i.split(',')[1]} |\n")

                f.close()

