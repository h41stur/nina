import asyncio
import sys

from nina import __main__

def main():
    OS = sys.platform
    if OS == "win32":
        import multiprocessing

        multiprocessing.freeze_support()
        asyncio.DefaultEventLoopPolicy = asyncio.WindowsSelectorEventLoopPolicy
    else:
        import uvloop

        uvloop.install()

        if "linux" in OS:
            import aiomultiprocess

            aiomultiprocess.set_context("fork")
        asyncio.run(__main__.initial())