import asyncio
import ssl
import socket
import sys
from typing import List
from nina.lib.colors import *

# threading
try:
    import concurrent.futures
except ImportError:
    warning_message("Nina needs python 3.4 > ro run!")
    sys.exit()

class SSLInformation:
    def __init__(self, domain, store, DATA_DIR, report_path, subs, THREADS):
        self.domain = domain
        self.store = store
        self.DATA_DIR = DATA_DIR
        self.report_path = report_path
        self.subs = subs
        self.THREADS = THREADS
        self.result: List[str] = list()
        self.partial: List[str] = list()
        self.values = {}


    def parse(self, value, key) -> None:
        dec = 0
        for i in value:
            if isinstance(i, tuple):
                for s in i:
                    if isinstance(s, tuple):
                        for e in s:
                            if isinstance(e, tuple):
                                self.parse(e)
                            else:
                                dec = 1
                        if dec:
                            self.values.update(dict([s]))
                    else:
                        pass
            else:
                d = {key: value}
                if d not in self.partial:
                    self.partial.append(d)

    def extract_ssl(self, s, DATA_DIR):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        try:
            sock.connect((s, 443))
            sock.close()
            context = ssl.create_default_context()
            sock = socket.socket()
            sock.settimeout(5)
            sock = context.wrap_socket(sock, server_hostname=s)

            try:
                sock.connect((s, 443))
                cert_info = sock.getpeercert()
            except:
                info = ssl.get_server_certificate((s, 443))
                file = open(f"{DATA_DIR}/{s}.pem", "w")
                file.write(info)
                file.close()
                cert_info = ssl._ssl._test_decode_cert(f"{DATA_DIR}/{s}.pem")
                os.remove("{self.DATA_DIR}/{s}.pem")

            for key, value in cert_info.items():
                if isinstance(value, tuple):
                    self.parse(value, key)
                    for key, value in self.values.items():
                        d = {key: value}
                        if d not in self.partial:
                            self.partial.append(d)
                    self.values.clear()
                else:
                    d = {key: value}
                    if d not in self.partial:
                        self.partial.append(d)
            sock.close()

            if self.partial is not None:
                resp = {"URL": s, "info": self.partial}
                return resp

        except:
            sock.close()
            print(f"[{RED}-{RESET}] An error has ocurred or unable to enumerate {RED}{s}")
            pass

    async def ssl_information(self) -> None:
        running_message("Extracting information from SSL Certificate...\n")
        asyncio.sleep(0.2)
        if self.domain not in self.subs:
            self.subs.append(self.domain)

        pool = concurrent.futures.ThreadPoolExecutor(max_workers=self.THREADS)
        data = (pool.submit(self.extract_ssl, s, self.DATA_DIR) for s in self.subs)
        for resp in concurrent.futures.as_completed(data):
            resp = resp.result()
            if resp is not None:
                self.result.append(resp)

        if self.result:
            for pair in self.result:
                print(f"\n[{GREEN}+{RESET}] Results from {YELLOW}{pair['URL']}\n")
                for i in pair["info"]:
                    for key, value in i.items():
                        if isinstance(value, tuple):
                            value = value[0]
                        print(f"{GREEN}-{RESET} {key}: {GREEN}{value}")
            if self.store:
                f = open(self.report_path, "a")
                f.write(f"\n\n## SSL Certificate Information\n")
                for pair in self.result:
                    f.write(f"\n### Results from {pair['URL']}\n")
                    f.write("|" + " KEY \t\t\t\t| VALUE \t\t\t|\n" + "|" + "-" * 47 + "|" + "-" * 23 + "|\n")
                    for i in pair["info"]:
                        for key, value in i.items():
                            if isinstance(value, tuple):
                                value = value[0]
                            f.write(f"| {key} | {value} |\n")
                f.close()

        else:
            warning_message(f"No SSL information found from {self.domain}")



