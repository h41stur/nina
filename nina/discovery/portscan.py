import ssl
import socket
import sys
import asyncio
from nina.lib.colors import *
from nina.lib.core import Core

# threading
try:
    import concurrent.futures
except ImportError:
    warning_message("Nina needs python 3.4 > ro run!")
    sys.exit(1)
    
class PortScan:
    def __init__(self, domain, store, report_path, subs, THREADS):
        self.domain = domain
        self.store = store
        self.report_path = report_path
        self.subs = subs
        self.THREADS = THREADS
        self.top_ports = Core.get_top_ports()

    @staticmethod
    def portscan_request(sub, p):
        banner = None
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1)
        try:
            status = s.connect_ex((sub, p))
            s.close()
        except socket.gaierror:
            return None

        if status == 0:
            print(f"{GREEN}-{RESET} Discovered open port: {GREEN}{sub} {YELLOW}{p}")

            context = ssl._create_unverified_context()
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(4)
            try:
                s.connect((sub, p))
                s = context.wrap_socket(s, server_hostname=sub)
                s.send("Nina\r\n".encode())
                banner = s.recv(200).decode('utf-8', 'ignore').split("\r\n\r\n")[0].strip()
                s.close()
            except (TimeoutError, ssl.SSLError, ConnectionResetError):
                s.close()
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(2)
                try:
                    s.connect((sub, p))
                    s.send("Nina\r\n".encode())
                    banner = s.recv(200).decode('utf-8', 'ignore')
                    banner = banner.split("\r\n\r\n")[0].strip()
                except (TimeoutError, ssl.SSLError, ConnectionResetError):
                    banner = None
                    s.close()
                s.close()

            return [p, banner]
        else:
            return None

    async def portscan(self) -> None:
        running_message("Portscanning...\n")
        asyncio.sleep(0.2)

        if self.domain not in self.subs:
            self.subs.append(self.domain)

        scan = []
        results = {}

        for sub in self.subs:
            pool = concurrent.futures.ThreadPoolExecutor(max_workers=self.THREADS)
            data = (pool.submit(self.portscan_request, sub, p) for p in self.top_ports)
            for resp in concurrent.futures.as_completed(data):
                resp = resp.result()
                if resp is not None and resp not in scan:
                    scan.append(resp)
            if scan:
                results.update({sub: scan})
                scan = []

        if results:
            running_message("Trying to get some banners...")
            if self.store:
                f = open(self.report_path, "a")
                f.write(f"\n\n## Portscan Results\n\n")
                f.close()
            for i in results:
                print(f"\n[{GREEN}+{RESET}] ports from {YELLOW}{i}\n")
                if self.store:
                    f = open(self.report_path, "a")
                    f.write(f"\n\n### Ports from **{i}**\n\n")
                    for p in results[i]:
                        f.write(f"- Discovered open port: **{i}:{p[0]}**\n")
                    f.write("\n### Banners grabbed:\n")
                    f.close()
                for p in results[i]:
                    if p[1] is not None:
                        print(f"{GREEN}-{RESET} Port {YELLOW}{p[0]}{RESET}:", end="\n\n")
                        print(f"{GREEN}{p[1]}", end="\n\n")
                        if self.store:
                            f = open(self.report_path, "a")
                            f.write(f"\n- Port {p[0]}.\n\n")
                            f.write(f"```\n{p[1]}\n```\n\n")
                            f.close()

        else:
            warning_message("Unable to enumerate any open port!")





