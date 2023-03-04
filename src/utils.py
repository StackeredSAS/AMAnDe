#!/usr/bin/env python3

from termcolor import *
import logging
import requests


class CustomFormatter(logging.Formatter):
    def format(self, record):
        if record.levelno == logging.INFO:
            pass
        elif record.levelno == logging.WARNING:
            record.msg = colored('[-] %s' % record.msg, "yellow")
        elif record.levelno == logging.CRITICAL:
            record.msg = colored('[!] %s' % record.msg, "red")
        elif record.levelno == logging.ERROR:
            record.msg = colored('[X] %s' % record.msg, "red")
        else:
            print("[!] Logging level not recognized")

        return super(CustomFormatter, self).format(record)


def str2Bool(s):
    """
    Associates true or false string with their corresponding boolean
    """
    if s == "true":
        return True
    elif s == "false":
        return False
    else:
        return None


def getResourceTypeName(value):
    """
    Parses resources like @XXX/XXX and gets their values
    """
    path = ""
    if value is not None:
        resType, value = value.strip("@").split("/")
        if resType == "string":
            path += "strings.xml"
        if resType == "xml":
            path += f"{value}.xml"
            value = None
        if resType == "raw":
            path += value
            value = None
    return path, value


def printTestInfo(title):
    """
    Formats titles
    """
    print(colored(f"\n[*] {title}", "blue", attrs=['bold']))


def printSubTestInfo(title):
    """
    Formats subtitles (useful when there are multiple subtests associated with a kind of test)
    """
    print(colored(f"\n[+] {title}", "cyan"))


def checkDigitalAssetLinks(host):
    """
    Checks if Digital Asset Link JSON file is publicly available
    """
    try:
        if requests.get(f'https://{host}/.well-known/assetlinks.json').status_code == 200:
            return True
    except requests.exceptions.ConnectionError:
        return False


def formatResource(path, name):
    """
    Formats a file name by adding an underline.
    If the resource is a string object, because we can't resolve the real value we format it like :
    strings.xml(value_name)
    This means the string can be found in the strings.xml file under the key "value_name".
    """
    filename = path
    res = colored(f"{filename}", attrs=["underline"])
    if name:
        # we have a string resource
        res = f"{res}({name})"
    return res


def unformatFilename(name):
    """
    Because Parser._getResValue formats filenames in a specific way
    we must undo the formatting to work with the raw string
    """
    return name[4:-4]


def runProc(*args, **kwargs):
    """
    Launches a subprocess that kills itself when its parent dies.

    :param args: The arguments to launch the subprocess.
    :type args: list[str]

    :return: The STDOUT and STDERR output of the subprocess launched or None if the program does not exist.
    :rtype: (bytes, bytes)

    """
    import subprocess
    p = None
    output = None
    output_stderr = None
    try:
        p = subprocess.Popen(stdout=subprocess.PIPE, stderr=subprocess.PIPE, *args, **kwargs)
        p.wait()
        output = p.stdout.read()
        output_stderr = p.stderr.read()
        p.stdout.close()
    finally:
        if p is not None and p.poll() is None:
            p.terminate()  # send sigterm, or ...
            p.kill()  # send sigkill
        return output, output_stderr


def handleVersion(lower_func, higher_func, trigger, min_sdk, target_sdk, is_target_sdk_trigger):
    """
    A convenient function to handle the case when a feature might exist only in a specific SDK version range,
    but the app can be installed on devices supporting a wider range of versions.

    Example:
        feature A is activated for SDK >= 20.
        lower_func is a function handling SDK < 20
        higher_func is a function handling SDK >= 20

        App supports only SDK versions < 20:
            feature A is activated, lower_func is called
        App supports only SDK versions >= 20:
            feature A is deactivated, higher_func is called
        App supports SDK versions in the range [17, 23]:
            feature A is activated for versions in [17, 19], lower_func is called
            feature A is deactivated for versions in [20, 23], higher_func is also called

    :param lower_func: Function taking a single boolean argument indicating if we need to print the condition.
    :param higher_func: Function taking a single boolean argument indicating if we need to print the condition.
    :param trigger: The SDK version indicating to switch to higher_func.
                    If the target version is equal to the trigger, the higher_func will be executed.
    :param min_sdk: The minimal SDK version supported by the app.
    :param max_sdk: The minimal SDK version supported by the app.
    :return: the return values of lower_func or higher_func, or both.
    """
    if is_target_sdk_trigger:
        if target_sdk < trigger:
            return lower_func()
        elif target_sdk >= trigger:
            return higher_func()
    else:
        a = lower_func(True)
        b = higher_func(True)
        if target_sdk >= trigger :
            if min_sdk < trigger:
                    return a, b
            return b
        return a

# si la version de target SDK est censée être le trigger alors on agit comme suit : 
# - si target sdk < trigger -> lower
# - si target sdk > trigger -> higher

# si la version de target SDK n'est pas censée être le trigger (la valeur de retour dépend de 
# la version installée sur le téléphone -> encrypted backup) alors on agit comme suit :

# on récupère les valeurs de retour de lower et higher
# if target SDK est inférieur à trigger, alors on retourne toujours lower
# sinon, on regarde si min sdk est inférieur à trigger et on retourne le tuple des 2 fonctions
# sinon on retourne juste higher