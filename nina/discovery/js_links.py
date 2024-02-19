import re
import sys
import html
import jsbeautifier
import ssl
import urllib3
import warnings
import asyncio
from gzip import GzipFile
from nina.lib.colors import *
from nina.lib.core import Core

# threading
try:
    import concurrent.futures
except ImportError:
    warning_message("Nina needs python 3.4 > ro run!")
    sys.exit()


urllib3.disable_warnings()
warnings.simplefilter("ignore")

try:
    from StringIO import StringIO
    readBytesCustom = StringIO
except ImportError:
    from io import BytesIO
    readBytesCustom = BytesIO

try:
    from urllib.request import Request, urlopen
except ImportError:
    from urllib3 import Request, urlopen

class JSLinks:
    def __init__(self, domain, store, report_path, subs, THREADS):
        self.domain = domain
        self.store = store
        self.report_path = report_path
        self.subs = subs
        self.THREADS = THREADS
        self.context = ssl._create_unverified_context()
        self.regex = Core.get_regex_pattern()

    def request_url(self, u):
        r = Request(u)
        r.add_header('User-Agent', Core.user_agent_list())
        r.add_header('Accept', 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8')
        r.add_header('Accept-Language', 'en-US,en;q=0.8')
        r.add_header('Accept-Encoding', 'gzip')

        resp = urlopen(r, timeout=4, context=self.context)

        if resp.info().get('Content-Encoding') == 'gzip':
            js = GzipFile(fileobj=readBytesCustom(resp.read())).read()
        elif resp.info().get('Content-Encoding') == 'deflate':
            js = resp.read().read()
        else:
            js = resp.read()

        return js.decode('utf-8', 'replace')

    def parsinf_js(self, js, regex):
        content = jsbeautifier.beautify(js)
        rgx = re.compile(regex, re.VERBOSE)
        elements = [{"link": m.group(1)} for m in re.finditer(rgx, content)]
        clean_links = []
        for e in elements:
            if e["link"] not in clean_links:
                clean_links.append(e)
        elements = clean_links

        return elements

    def execution(self, u):
        endpoints = []

        for schema in ('https://', 'http://'):
            url = f"{schema}{u}"
            try:
                js = self.request_url(url)
                edp = self.parsinf_js(js, self.regex)
                for e in edp:
                    url_js = html.escape(e["link"]).encode(
                        'ascii', 'ignore'
                    ).decode('utf8')
                    if url_js not in endpoints:
                        endpoints.append(url_js)
            except:
                pass
            if endpoints:
                print(f"\n[{GREEN}+{RESET}] {u}\n")
                for e in endpoints:
                    print(f"\t{GREEN}-{RESET} {e}")
                return {u: endpoints}

    def js_links(self) -> None:
        running_message("Searching for endpoints in JS files...\n")
        asyncio.sleep(0.2)
        if self.domain not in self.subs:
            self.subs.append(self.domain)

        endpoints = []

        pool = concurrent.futures.ThreadPoolExecutor(max_workers=self.THREADS)
        data = (pool.submit(self.execution, s) for s in self.subs)
        for resp in concurrent.futures.as_completed(data):
            resp = resp.result()
            if resp is not None and resp not in endpoints:
                endpoints.append(resp)

        if endpoints:
            if self.store:
                f = open(self.report_path, "a")
                f.write(f"\n\n## Endpoints and parameters in JavaScript\n\n")
                for e in endpoints:
                    for k, v in e.items():
                        f.write(f"\n\n### Endpoints and parameters from **{k}**\n\n")
                        for i in v:
                            f.write(f"- {i}\n")
                f.close()
        else:
            warning_message("No endpoints or parameters found.")










