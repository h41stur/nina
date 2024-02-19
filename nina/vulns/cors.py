import requests
import json
import sys
import urllib3
import warnings
import asyncio
from typing import List
from nina.lib.colors import *
from nina.lib.core import Core
from urllib.parse import urlparse


urllib3.disable_warnings()
warnings.simplefilter("ignore")

# threading
try:
    import concurrent.futures
except ImportError:
    warning_message("Nina needs python 3.4 > ro run!")
    sys.exit()

class Cors:
    def __init__(self, domain, store, report_path, subs, DATA_DIR, vulnerability, THREADS):
        self.domain = domain
        self.store = store
        self.report_path = report_path
        self.subs = subs
        self.DATA_DIR = DATA_DIR
        self.vulnerability = vulnerability
        self.THREADS = THREADS
        self.schemas = ['http://', 'https://']

    def cors_testing(self, endpoint, headers):
        try:
            r = requests.get("https://raw.githubusercontent.com/h41stur/nina/main/nina/data/references_recon.json",
                             verify=False, timeout=20)
            CORS_VULN = json.loads(r.text)
            CORS_VULN = CORS_VULN["CORS"]
        except:
            with open(self.DATA_DIR / "references_recon.json", "r") as file:
                CORS_VULN = json.load(file)
                CORS_VULN = CORS_VULN["CORS"]

        try:
            # Origin reflected
            origin = 'https://h41stur.com'
            headers['Origin'] = origin
            header = ''
            r = requests.get(endpoint, headers=headers, verify=False, timeout=5)
            h = r.headers
            for key, value in h.items():
                if key.lower() == 'access-control-allow-origin':
                    header = h
                if header:
                    acao, acac = header.get('access-control-allow-origin', None), header.get(
                        'access-control-allow-credentials', None
                    )
                    if acao and acao == (origin):
                        data = CORS_VULN['origin reflected']
                        data['acao header'] = acao
                        data['acac header'] = acac
                        return {endpoint: data}

            # post-domain wildcard
            origin = f'https://{self.domain}.h41stur.com'
            headers['Origin'] = origin
            header = ''
            r = requests.get(endpoint, headers=headers, verify=False, timeout=5)
            h = r.headers
            for key, value in h.items():
                if key.lower() == 'access-control-allow-origin':
                    header = h
                if header:
                    acao, acac = header.get('access-control-allow-origin', None), header.get(
                        'access-control-allow-credentials', None
                    )
                    if acao and acao == (origin):
                        data = CORS_VULN['post-domain wildcard']
                        data['acao header'] = acao
                        data['acac header'] = acac
                        return {endpoint: data}

            # pre-domain wildcard
            origin = f'https://h41stur{self.domain}'
            headers['Origin'] = origin
            header = ''
            r = requests.get(endpoint, headers=headers, verify=False, timeout=5)
            h = r.headers
            for key, value in h.items():
                if key.lower() == 'access-control-allow-origin':
                    header = h
                if header:
                    acao, acac = header.get('access-control-allow-origin', None), header.get(
                        'access-control-allow-credentials', None
                    )
                    if acao and acao == (origin):
                        data = CORS_VULN['pre-domain wildcard']
                        data['acao header'] = acao
                        data['acac header'] = acac
                        return {endpoint: data}

            # null origin allowed
            origin = 'null'
            headers['Origin'] = origin
            header = ''
            r = requests.get(endpoint, headers=headers, verify=False, timeout=5)
            h = r.headers
            for key, value in h.items():
                if key.lower() == 'access-control-allow-origin':
                    header = h
                if header:
                    acao, acac = header.get('access-control-allow-origin', None), header.get(
                        'access-control-allow-credentials', None
                    )
                    if acao and acao == (origin):
                        data = CORS_VULN['null origin allowed']
                        data['acao header'] = acao
                        data['acac header'] = acac
                        return {endpoint: data}

            # unrecognized underscore
            origin = f'https://{self.domain}_.h41stur.com'
            headers['Origin'] = origin
            header = ''
            r = requests.get(endpoint, headers=headers, verify=False, timeout=5)
            h = r.headers
            for key, value in h.items():
                if key.lower() == 'access-control-allow-origin':
                    header = h
                if header:
                    acao, acac = header.get('access-control-allow-origin', None), header.get(
                        'access-control-allow-credentials', None
                    )
                    if acao and acao == (origin):
                        data = CORS_VULN['unrecognized underscore']
                        data['acao header'] = acao
                        data['acac header'] = acac
                        return {endpoint: data}

            # broken parser
            origin = f'https://{self.domain}%60.h41stur.com'
            headers['Origin'] = origin
            header = ''
            r = requests.get(endpoint, headers=headers, verify=False, timeout=5)
            h = r.headers
            for key, value in h.items():
                if key.lower() == 'access-control-allow-origin':
                    header = h
                if header:
                    acao, acac = header.get('access-control-allow-origin', None), header.get(
                        'access-control-allow-credentials', None
                    )
                    if acao and '`.h41stur.com' in acao:
                        data = CORS_VULN['broken parser']
                        data['acao header'] = acao
                        data['acac header'] = acac
                        return {endpoint: data}

            # unescaped regex
            loc = urlparse(endpoint).netloc
            if loc.count(".") > 1:
                origin = f'https://{loc.replace(".", "x", 1)}'
                headers['Origin'] = origin
                r = requests.get(endpoint, headers=headers, verify=False, timeout=5)
                h = r.headers
                for key, value in h.items():
                    if key.lower() == 'access-control-allow-origin':
                        header = h
                    if header:
                        acao, acac = header.get('access-control-allow-origin', None), header.get(
                            'access-control-allow-credentials', None)
                        if acao and acao == (origin):
                            data = CORS_VULN['unescaped regex']
                            data['acao header'] = acao
                            data['acac header'] = acac
                            return {endpoint: data}

            # http origin allowed
            origin = f'http://{self.domain}'
            headers['Origin'] = origin
            header = ''
            r = requests.get(endpoint, headers=headers, verify=False, timeout=5)
            h = r.headers
            for key, value in h.items():
                if key.lower() == 'access-control-allow-origin':
                    header = h
                if header:
                    acao, acac = header.get('access-control-allow-origin', None), header.get(
                        'access-control-allow-credentials', None
                    )
                    if acao and acao.startswith('http://'):
                        data = CORS_VULN['http origin allowed']
                        data['acao header'] = acao
                        data['acac header'] = acac
                        return {endpoint: data}

            # wildcard value and third party allowed
            loc = urlparse(endpoint).netloc
            origin = f'https://{self.domain}'
            headers['Origin'] = origin
            header = ''
            r = requests.get(endpoint, headers=headers, verify=False, timeout=5)
            h = r.headers
            for key, value in h.items():
                if key.lower() == 'access-control-allow-origin':
                    header = h
                if header:
                    acao, acac = header.get('access-control-allow-origin', None), header.get(
                        'access-control-allow-credentials', None
                    )
                    if acao and acao == "*":
                        data = CORS_VULN['wildcard value']
                        data['acao header'] = acao
                        data['acac header'] = acac
                        return {endpoint: data}

                    if loc:
                        if urlparse(acao).netloc and urlparse(acao).netloc != loc:
                            data = CORS_VULN['third party allowed']
                            data['acao header'] = acao
                            data['acac header'] = acac
                            return {endpoint: data}

        except requests.exceptions.RequestException as e:
            if 'Failed to establish a new connection' in str(e):
                print(f"[{YELLOW}!{RESET}] URL {endpoint} is unreachable")
            elif 'requests.exceptions.TooManyRedirects:' in str(e):
                print(f"[{YELLOW}!{RESET}] URL {endpoint} has too many redirects")

    async def cors(self) -> None:
        running_message("Searching for CORS misconfiguration...\n")
        asyncio.sleep(0.2)
        if self.domain not in self.subs:
            self.subs.append(self.domain)

        headers = {
            'User-Agent': Core.user_agent_list(),
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip',
            'DNT': '1',
            'Connection': 'close',
        }

        endpoints: List[str] = list()
        scan: List[str] = list()

        for s in self.subs:
            for schema in self.schemas:
                u = schema + s
                if u not in endpoints and "*" not in u:
                    endpoints.append(u)

        # iterating on endpoints
        if endpoints:
            pool = concurrent.futures.ThreadPoolExecutor(max_workers=self.THREADS)
            data = (pool.submit(self.cors_testing, endpoint, headers) for endpoint in endpoints)
            for resp in concurrent.futures.as_completed(data):
                resp = resp.result()
                if resp is not None and resp not in scan:
                    scan.append(resp)

            if scan:
                if self.store:
                    f = open(self.report_path, "a")
                    f.write(f"\n\n## CORS misconfigurations\n\n")
                    f.close()
                for resp in scan:
                    for i in resp:
                        print(f"\n[{GREEN}+{RESET}] {i}")
                        print(f"\t{GREEN}-{RESET} Type: {resp[i]['class']}")
                        print(f"\t{GREEN}-{RESET} Description: {resp[i]['description']}")
                        print(f"\t{GREEN}-{RESET} Severity: {resp[i]['severity']}")
                        print(f"\t{GREEN}-{RESET} Exploit: {resp[i]['exploitation']}")
                        print(f"\t{GREEN}-{RESET} ACAO Header: {resp[i]['acao header']}")
                        print(f"\t{GREEN}-{RESET} ACAC header: {resp[i]['acac header']}")
                        self.vulnerability.append(f"WEB, CORS Misconfiguration, Certain, {resp[i]['severity']}, URL: {i}")
                        if self.store:
                            f = open(self.report_path, "a")
                            f.write(f"\n\n### {i}\n\n")
                            f.write(f"\n- Type: {resp[i]['class']}")
                            f.write(f"\n- Description: {resp[i]['description']}")
                            f.write(f"\n- Severity: {resp[i]['severity']}")
                            f.write(f"\n- Exploit: {resp[i]['exploitation']}")
                            f.write(f"\n- ACAO Header: {resp[i]['acao header']}")
                            f.write(f"\n- ACAC Header: {resp[i]['acac header']}")
                            f.close()
            else:
                warning_message("No CORS misconfiguration found.")

