#!/usr/bin/env python3

from termcolor import *
import logging
import requests


class CustomFormatter(logging.Formatter):
    def format(self, record):
        #TODO : updating to python 3.10 before replacing following code with this
        '''
        match record.levelno:
            case logging.INFO:
                record.msg = colored('[+] %s' % (record.msg),"blue")
            case logging.WARNING:
                #record.msg = '[%s] %s' % ("[-]", record.msg)
                record.msg = colored('[-] %s' % (record.msg),"yellow")
            case logging.ERROR:
                record.msg = colored('[!] %s' % (record.msg),"red")
            case _:
                print("[!] Logging level not recognized")
        '''

        #datetime.date.today().strftime("%m/%d %H:%M:%S")
        if record.levelno == logging.INFO:
                pass
        elif record.levelno == logging.WARNING:
                record.msg = colored('[-] %s' % (record.msg), "yellow")
        elif record.levelno == logging.CRITICAL:
                record.msg = colored('[!] %s' % (record.msg), "red")
        else:
            print("[!] Logging level not recognized")

        return super(CustomFormatter , self).format(record)


def str2Bool(s):
    if s == "true":
        return True
    elif s == "false":
        return False
    else:
        return None


def getResourceTypeName(value):
    # ca ne sert plus à rien de renvoyer le path en fait
    # a voir pour le virer
    path = "res/"
    if value is not None:
        resType, value = value.strip("@").split("/")
        if resType == "string":
            path += "values/strings.xml"
        if resType == "xml":
            path += f"xml/{value}.xml"
            value = None
    return path, value


def printTestInfo(title):
    print(colored(f"\n[*] {title}", "blue"))


def printSubTestInfo(title):
    print(colored(f"\n[+] {title}", "cyan"))


def checkDigitalAssetLinks(host):
    try:
        if requests.get(f'https://{host}/.well-known/assetlinks.json').status_code == 200:
            return True
    except Exception:
        return False

def unformatFilename(name):
    # because Parser._getResValue formats filenames in a specific way
    # we must undo the formatting to work with the raw string
    return name[4:-4]

def runProc(*args, **kwargs):
    """
    Launches a subprocess that kills itself when its parent dies.

    :param args: The arguments to launch the subprocess.
    :type args: list[str]

    :return: The STDOUT output of the subprocess launched or None if the program does not exist.
    :rtype: bytes

    **Examples** ::

        >>> runProc(["pwd"])
        b'/tmp/test\\n'
        >>> runProc(["echo", "hello"])
        b'hello\\n'
    """
    import subprocess
    p = None
    output = None
    try:
        p = subprocess.Popen(stdout=subprocess.PIPE, *args, **kwargs)
        p.wait()
        output = p.stdout.read()
        p.stdout.close()
    finally:
        if p is not None and p.poll() is None:
            p.terminate()  # send sigterm, or ...
            p.kill()  # send sigkill
        return output

