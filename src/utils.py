#!/usr/bin/env python3

from termcolor import *
import logging


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
        elif record.levelno == logging.ERROR:
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
    return value.split("/")[1] if value != None else None

