from .config import EXTERNAL_BINARIES
from .utils import (
    runProc,
    printSubTestInfo
)
from termcolor import colored


def runAPKSigner(logger, min_sdk, path):
    cmd = EXTERNAL_BINARIES["apksigner"] + ["verify", "--print-certs", "--verbose", "--min-sdk-version",
                                            str(min_sdk), path]
    cmdres = runProc(cmd)
    if cmdres:
        printSubTestInfo("Output of apksigner")
        logger.info(colored(f"executed command : {' '.join(cmd)}", "yellow"))
        logger.info(cmdres.decode())