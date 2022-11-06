from .config import EXTERNAL_BINARIES
from .utils import (
    runProc,
    printSubTestInfo
)
from termcolor import colored
import re


def runAPKSigner(logger, min_sdk, path):
    cmd = EXTERNAL_BINARIES["apksigner"] + ["verify", "--print-certs", "--verbose", "--min-sdk-version",
                                            str(min_sdk), path]
    cmdres = runProc(cmd)
    pattern_1 = ".*Unauthorized.*not be detected.*$"

    if cmdres:
        printSubTestInfo("Output of apksigner")
        logger.info(colored(f"executed command : {' '.join(cmd)}", "yellow"))

        # Only get lines that contains signature schemes info (take into account v1, v2, v3 and v4)
        signature_checks = cmdres.decode().splitlines()[1:5]
        counter = 0

        for line in cmdres.decode().splitlines():
            if line.startswith("WARNING:") and re.match(pattern_1, line):
                counter += 1
            else:
                print(line)

        if "true" in signature_checks[0] and not any("true" in s for s in signature_checks[1:]) and counter != 0:
            logger.critical("Your APK is only signed with scheme v1. Unauthorized modification to META-INF jar "
                            "entry will not be detected")

