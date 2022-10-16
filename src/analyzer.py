from termcolor import colored
from tabulate import tabulate
from .utils import CustomFormatter
import logging
from .constants import *


class Analyzer():

    def __init__(self, parser, args):
        self.parser = parser
        self.args = args
        self.logger = logging.getLogger(__name__)
        self.setLogLevel(args.log_level)

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
        elif level == "CRITICAL":
            self.logger.setLevel(logging.ERROR)
        else:
            raise NotImplementedError("Unknown logging level")

    def analyseBuiltinsPerms(self):
        self.logger.info("on analyse les perms bla bla")
        header = ["builtin Permissions"]
        table = []

        for perm in self.parser.builtinsPermissions():
            if perm in dangerous_perms:
                perm = colored(perm, "red")

            table.append([perm])
        self.logger.info(tabulate(table, header, tablefmt="github"))
        # ajouter la logique
        self.logger.critical(f"Found vulnerable perms : android.permission.ACCESS_NETWORK_STATE")

    def isADBBackupAllowed(self):
        self.logger.info("Analyzing backup functionnality (adb)")
        backup_attr = self.parser.allowBackup()

        # android:allowBackup default value is true
        if backup_attr or backup_attr is None:
            self.logger.info("adb backup can be performed")
            return True
        self.logger.info("APK can not be backuped with adb")
        return False

    def isAutoBackupAllowed(self):
        self.logger.info("Analyzing backup functionnality (Auto backup)")
        backup_attr = self.parser.allowBackup()
        MaxAPILevel = self.args.max_sdk_version

        # android:allowBackup default value is true (auto backup available for API >= 23)
        if (backup_attr or backup_attr is None) and MaxAPILevel >= 23:
            self.logger.warning("Auto backup funtionnality is activated (end-to-end encrypted Google drive backup for device running Android 9 or higher) and adb backup can be performed")
            return True
        self.logger.info("APK can not be backuped with Auto Backup")
        return False

    def isBackupAgentImplemented(self):
        self.logger.info("Checking for own developper backup agent")
        agent = self.parser.backupAgent()
        if agent:
            self.logger.warning(
                f'APK implements is own backup agent in {agent.split(".")[-1]}. Please make deeper checks')
            return True
        self.logger.info("No backup agent implementation has been found")
        return False

    def getBackupRulesFile(self):
        self.logger.info("Analyzing backup functionnality")
        fullBackupContent_xml_file_rules = self.parser.fullBackupContent()
        # taking into account android 12 backup attribute dataExtractionRules
        dataExtractionRules_xml_rules_files = self.parser.dataExtractionRules()

        res = 0
        if fullBackupContent_xml_file_rules is not None:
            self.logger.info(f'Custom rules has been defined to control what gets backed up in "{fullBackupContent_xml_file_rules}" file')
            res |= 1
        if dataExtractionRules_xml_rules_files is not None:
            self.logger.info(f'Custom rules has been defined to control what gets backed up in "{dataExtractionRules_xml_rules_files}" file')
            res |= 2
            return res
        self.logger.warning("fullBackupContent or dataExtractionRules properties not found. Please make a backup for further controls")
        return res

    def getNetworkConfigFile(self):
        self.logger.info("Checking existence of network_security_config XML file")
        network_security_config_xml_file = self.parser.networkSecurityConfig()
        if network_security_config_xml_file is not None:
            self.logger.info(f'APK network security configuration is defined in "{network_security_config_xml_file}" file')
            return True
        self.logger.warning("networkSecurityConfig property not found")
        return False

    # Pay attention : Check the default value of exported property for services, broadcast receiver etc.
    def runAllTests(self):
        #self.analyseBuiltinsPerms()
        # isBackupAllowed = self.isBackupAllowed()
        #isADBBackupAllowed = self.isADBBackupAllowed()
        #isAutoBackupAllowed = self.isAutoBackupAllowed()
        #if isADBBackupAllowed or isAutoBackupAllowed:
            #self.getBackupRulesFile()
        #self.getNetworkConfigFile()
        #self.isBackupAgentImplemented()

        # showcase parser unused features
        print("-" * 20)
        print(f"{self.parser.debuggable()=}")
        print(f"{self.parser.usesCleartextTraffic()=}")
        for e in self.parser.customPermissions():
            print(f"{e.name} | {e.permissionGroup} | {e.protectionLevel}")
        print(self.parser.exportedServices())
