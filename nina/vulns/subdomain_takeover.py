import requests
import dns.resolver
import sys
from time import sleep
from nina.lib.colors import *

import urllib3
import warnings
urllib3.disable_warnings()
warnings.simplefilter("ignore")

# threading
try:
    import concurrent.futures
except ImportError:
    warning_message("Nina needs python 3.4 > ro run!")
    sys.exit()

class SubTake:
    def __init__(self, domain, store, subs, report_path, THREADS):
        self.domain = domain
        self.store = store
        self.subs = subs
        self.report_path = report_path
        self.THREADS = THREADS

    @staticmethod
    def subtake_request(s):

        try:
            r = requests.get(f"https://{s}", verify=False, allow_redirects=False, timeout=4)
            if str(r.status_code) == "404":
                query = dns.resolver.resolve(s, 'CNAME')
                for q in query:
                    q = (q.to_text())
                    if s[-8:] not in q:
                        print(f"\t{GREEN}-{RESET} Possible subdomain takeover: {GREEN}{s}{RESET} pointing to {GREEN}{q}{RESET} with status {RED}404")
                        return f"{s},{q}"
                    else:
                        return None
            else:
                return None
        except:
            return None

    def sub_take(self) -> None:
        running_message("Checking for subdomain takeover vulnerability...\n")
        sleep(0.2)

        vulns = []

        pool = concurrent.futures.ThreadPoolExecutor(max_workers=self.THREADS)
        data = (pool.submit(self.subtake_request, s) for s in self.subs)
        for resp in concurrent.futures.as_completed(data):
            resp = resp.result()
            if resp is not None and resp not in vulns:
                vulns.append(resp)

        if vulns:
            if self.store:
                f = open(self.report_path, "a")
                f.write(f"\n\n## Possible Subdomain Takeover\n\n")
                for v in vulns:
                    v = v.split(",")
                    sub = v[0]
                    point = v[1]
                    f.write(f"\n- **{sub}** pointing to **{point}**")
                f.close()
        else:
            warning_message("No subdomain vulnerable.")

