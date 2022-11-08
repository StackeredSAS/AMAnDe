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
    cmdres, err = runProc(cmd)
    pattern_1 = ".*Unauthorized.*not be detected.*$"

    if cmdres is not None:
        printSubTestInfo("Output of apksigner")
        logger.info(colored(f"executed command : {' '.join(cmd)}", "yellow"))

        signature_versions = [False, False, False]
        for line in cmdres.decode().splitlines():
            if line.startswith("WARNING:") and re.match(pattern_1, line):
                continue

            if "key size (bits)" in line:
                key_size = ["3072", "P-256", "P-384", "P-521", "4096", "8192", "16384"]
                line = line.replace("1024", colored("1024", "red"))
                line = line.replace("2048", colored("2048", "yellow"))
                for e in key_size:
                    line = line.replace(e, colored(e, "green"))

            if "APK Signature Scheme v2" in line:
                signature_versions[1] = ("true" in line)
                line = line.replace("true", colored("true", "green"))
                line = line.replace("false", colored("false", "red"))

            if "APK Signature Scheme v3" in line:
                signature_versions[2] = ("true" in line)
                line = line.replace("true", colored("true", "green"))
                line = line.replace("false", colored("false", "red"))

            if "JAR signing" in line:
                signature_versions[0] = ("true" in line)
                line = line.replace("true", colored("true", "green"))
                line = line.replace("false", colored("false", "red"))

            print(line)

        if signature_versions[0] and not any(signature_versions[1:]):
            logger.critical("Your APK is only signed with scheme v1. Unauthorized modification to META-INF jar "
                            "entry will not be detected")
