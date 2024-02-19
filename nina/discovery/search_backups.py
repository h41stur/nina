import asyncio
import sys
import urllib3
import warnings
import aiohttp
from typing import Union, List
from prettytable import PrettyTable
from nina.lib.colors import *
from nina.lib.core import Core


urllib3.disable_warnings()
warnings.simplefilter("ignore")

# threading
try:
    import concurrent.futures
except ImportError:
    warning_message("Nina needs python 3.4 > ro run!")
    sys.exit()

class SearchBkp:
    def __init__(self, domain, store, report_path, subs, THREADS):
        self.domain = domain
        self.store = store
        self.report_path = report_path
        self.subs = subs
        self.THREADS = THREADS
        self.ext = ["sql.tar", "tar", "tar.gz", "gz", "tar.bzip2", "sql.bz2", "sql.7z", "zip", "sql.gz", "7z"]
        self.hostname = self.domain.split(".")[0]
        self.filename = [self.hostname, self.domain, "backup", "admin", "wordpress"]
        self.proto = ["http://", "https://"]

    async def request_bkp(self, subdomain: str) -> Union[str, None]:
        headers = {
            "Host": subdomain,
            "User-Agent": Core.user_agent_list()
        }

        for p in self.proto:
            for f in self.filename:
                for e in self.ext:
                    URL = f"{p}{subdomain}/{f}.{e}"
                    try:
                        async with aiohttp.ClientSession(headers=headers) as sess:
                            async with sess.get(URL) as resp:
                                status = resp.status
                    except KeyboardInterrupt:
                        warning_message("Interrupt handler received, exiting...\n")
                    except:
                        continue
                    if status != 400:
                        return f"{URL},{status}"
                    else:
                        return None

    async def search_backups(self) -> None:
        running_message("Searching for backup files...\n")
        asyncio.sleep(0.2)
        if self.domain not in self.subs:
            self.subs.append(self.domain)

        bkp: List[str] = list()

        pool = concurrent.futures.ThreadPoolExecutor(max_workers=self.THREADS)
        data = (pool.submit(self.request_bkp, s) for s in self.subs)
        for resp in concurrent.futures.as_completed(data):
            resp = await resp.result()
            if resp is not None and resp not in bkp:
                bkp.append(resp)

        if bkp:
            if self.store:
                f = open(self.report_path, "a")
                f.write(f"\n\n## Backup files found\n\n")
                f.write("|" + " URL \t\t\t\t| STATUS \t\t\t|\n" + "|" + "-" * 47 + "|" + "-" * 23 + "|\n")

            table = PrettyTable(["URL", "STATUS"])
            for b in bkp:
                s = b.split(",")[0]
                v = b.split(",")[1]
                if self.store:
                    f = open(self.report_path, "a")
                    f.write(f"| {s} | {v} |\n")
                table.add_row([s, v])
                table.align["URL"] = "l"

            print(table)

            if self.store:
                f.close()

        else:
            warning_message("No backup files found")




