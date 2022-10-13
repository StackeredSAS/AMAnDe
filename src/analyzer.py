from termcolor import colored
from tabulate import tabulate
from .utils import CustomFormatter
import logging

class Analyzer():

    def __init__(self, parser):
        self.parser = parser
        self.logger = logging.getLogger(__name__)
        self.logger.setLevel(logging.INFO)

        # Create stdout handler for logging to the console (logs all five levels)
        stdout_handler = logging.StreamHandler()
        stdout_handler.setFormatter(CustomFormatter())
        # Add handlers to the logger
        self.logger.addHandler(stdout_handler)

    def setLogLevel(self, level):
        if level == "INFO":
            self.logger.setLevel(logging.INFO)
        elif level == "WARNING":
            self.logger.setLevel(logging.WARNING)
        elif level == "ERROR":
            self.logger.setLevel(logging.ERROR)
        else:
            raise NotImplementedError("Unknown logging level")

    def analyseBuiltinsPerms(self):
        self.logger.info("on analyse les perms bla bla")
        header = ["builtin Permissions"]
        table = []
        for perm in self.parser.builtinsPermissions():
            if perm == 'android.permission.ACCESS_NETWORK_STATE':
                perm = colored(perm, "red")
            if perm == 'android.permission.GET_ACCOUNTS':
                perm = colored(perm, "yellow")
            table.append([perm])
        self.logger.info(tabulate(table, header, tablefmt="github"))
        # ajouter la logique
        self.logger.error(f"Found vulnerable perms : android.permission.ACCESS_NETWORK_STATE")


    def isBackupAllowed(self):
        self.logger.info("Analyzing backup functionnality")
        backup_attr = self.parser.getBackupAttr()

        if backup_attr == None:
            self.logger.info("APK allowBackup property not found! From Android 6, the default value is true.")
        elif backup_attr:
            self.logger.info("APK can be backuped.")
        else:
            self.logger.info("APK can not be backuped")
        
        

    def runAllTests(self):
        self.analyseBuiltinsPerms()
        self.isBackupAllowed()

        # showcase parser unused features
        print("-"*20)
        print(f"{self.parser.debuggable()=}")
        print(f"{self.parser.usesCleartextTraffic()=}")
        for e in self.parser.customPermissions():
            print(f"{e.name} | {e.permissionGroup} | {e.protectionLevel}")
        print(self.parser.exportedServices())