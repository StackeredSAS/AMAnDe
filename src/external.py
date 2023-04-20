from .config import EXTERNAL_BINARIES, ADB_BACKUP_PATH
from .utils import (
    runProc,
    printSubTestInfo
)
from termcolor import colored
import re
import logging

logger = logging.getLogger("MainLogger")


def runAPKSigner(min_sdk, path):
    """
    Executes APKSigner if available.
    The output is interpreted and colored.
    Warnings are removed for readability.
    """
    cmd = EXTERNAL_BINARIES["apksigner"] + ["verify", "--print-certs", "--verbose", "--min-sdk-version",
                                            str(min_sdk), path]
    cmdres, err = runProc(cmd)
    pattern_1 = ".*Unauthorized.*not be detected.*$"
    jres = {}
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

            logger.info(line)

        jres["signature versions"] = {
            "V1": signature_versions[0],
            "V2": signature_versions[1],
            "V3": signature_versions[2]
        }
        if signature_versions[0] and not any(signature_versions[1:]):
            logger.critical("Your APK is only signed with scheme v1. Unauthorized modification to META-INF jar "
                            "entry will not be detected")
        return jres


def downloadAPK(name, new_path):
    """
    Downloads the APK associated to the package name using ADB.
    The resulting APK is always named base.apk.
    """
    cmd = EXTERNAL_BINARIES["adb"] + ["shell", "pm", "path", name]
    cmdres, err = runProc(cmd)
    if cmdres is None or cmdres == b'':
        logger.error(err.decode().strip())
        return
    logger.info(colored(f"executed command : {' '.join(cmd)}", "yellow"))
    path = cmdres.strip().split(b':')[1].decode()

    cmd = EXTERNAL_BINARIES["adb"] + ["pull", path, new_path]
    logger.info(f"Downloading APK {name} into {new_path}...")
    logger.info(colored(f"executing command : {' '.join(cmd)}", "yellow"))
    cmdres, err = runProc(cmd)
    if cmdres is None or cmdres == b'':
        logger.error(err.decode().strip())
        return
    return new_path + f"/base.apk"


def performBackup(name):
    """
    Performs an ADB backup and converts the resulting file to a TAR archive.
    The default backup file location can be changed in config.py.
    """
    # first open the app
    cmd = EXTERNAL_BINARIES["adb"] + ["shell", "monkey", "-p", name, "1"]
    logger.info(colored(f"executing command : {' '.join(cmd)}", "yellow"))
    cmdres, err = runProc(cmd)
    if cmdres is None or cmdres == b'':
        logger.error(err.decode().strip())
        return
    # now backup
    cmd = EXTERNAL_BINARIES["adb"] + ["shell", "bu", "backup", name]
    logger.info(f"Backing APK {name}. Waiting for user validation...")
    logger.info(colored(f"executing command : {' '.join(cmd)}", "yellow"))
    cmdres, err = runProc(cmd)
    if cmdres is None or cmdres == b'':
        logger.error(err.decode().strip())
        return
    # convert .ab to .tar
    header = b'\x1f\x8b\x08\x00\x00\x00\x00\x00'
    cmdres = header + cmdres[24:]
    with open(ADB_BACKUP_PATH, "wb") as f:
        f.write(cmdres)
    logger.info(f"Backup written to {ADB_BACKUP_PATH}")
