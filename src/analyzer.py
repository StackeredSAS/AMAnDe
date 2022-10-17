from termcolor import colored
from tabulate import tabulate
from .utils import CustomFormatter, printTestInfo, printSubTestInfo
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
        printTestInfo("Analyzing required builtin permissions")
        header = ["builtin Permissions"]
        table = []

        for perm in self.parser.builtinsPermissions():
            if perm in dangerous_perms:
                perm = colored(perm, "red")

            table.append([perm])
        self.logger.info(tabulate(table, header, tablefmt="github"))

    def isADBBackupAllowed(self):
        """
        Checks if ADB backups are allowed.
        https://developer.android.com/guide/topics/manifest/application-element#allowbackup
        :return: True if ADB backup is allowed, False otherwise.
        """
        printSubTestInfo("Checking for ADB backup functionality")
        backup_attr = self.parser.allowBackup()

        # android:allowBackup default value is true for any android version
        if backup_attr or backup_attr is None:
            self.logger.info("ADB backup can be performed")
            return True
        self.logger.info("APK cannot be backed up with adb")
        return False

    def isAutoBackupAllowed(self):
        """
        Checks if Auto Backup are allowed.
        https://developer.android.com/guide/topics/data/autobackup
        :return: True if Auto Backup is allowed, False otherwise.
        """
        printSubTestInfo("Checking for auto-backup functionality")
        backup_attr = self.parser.allowBackup()
        MaxAPILevel = self.args.max_sdk_version
        MinAPILevel = self.args.min_sdk_version

        # android:allowBackup default value is true for any android version but auto backup is only available for API >= 23
        if (backup_attr or backup_attr is None) and MaxAPILevel >= 23:
            msg = "Google drive Auto backup functionality is activated "
            # Android 9 => API level >= 28
            if MinAPILevel >= 28:
                msg += colored("(E2E encrypted)", "green")
            elif MaxAPILevel < 28:
                msg += colored("(E2E encryption not available)", "red")
            else:
                msg += colored("(E2E encryption is only available from Android 9 (API level 28))", "yellow")
            self.logger.info(msg)
            return True
        self.logger.info("APK cannot be backed up with Auto Backup")
        return False

    def isBackupAgentImplemented(self):
        """
        Checks if a backup agent is implemented as a Java/Kotlin class.

        .. note::
        https://developer.android.com/guide/topics/manifest/application-element#agent

        :return: True if a backupAgent property has been found in Manifest, False otherwise.
        """
        printSubTestInfo("Checking for own developer backup agent")
        agent = self.parser.backupAgent()
        if agent:
            self.logger.warning(
                f'APK implements is own backup agent in {agent.split(".")[-1]}. Please make deeper checks')
            return True
        self.logger.info("No backup agent implementation has been found")
        return False

    def getBackupRulesFile(self):
        """
        todo: vérifier si les 2 balises peuvent coexister
        """
        printSubTestInfo("Checking backup rules files")
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
        printTestInfo("Checking the existence of network_security_config XML file")
        network_security_config_xml_file = self.parser.networkSecurityConfig()
        if network_security_config_xml_file is not None:
            self.logger.info(f'APK network security configuration is defined in "{network_security_config_xml_file}" file')
            return True
        self.logger.warning("networkSecurityConfig property not found")
        return False

    def analyzeBackupFeatures(self):
        printTestInfo("Analyzing backup functionality")
        isADBBackupAllowed = self.isADBBackupAllowed()
        isAutoBackupAllowed = self.isAutoBackupAllowed()
        if isADBBackupAllowed or isAutoBackupAllowed:
            self.getBackupRulesFile()
        self.isBackupAgentImplemented()

    # Pay attention : Check the default value of exported property for services, broadcast receiver etc.
    def runAllTests(self):
        print(colored(f"Analysis of {self.args.path}", "magenta", attrs=["bold"]))
        '''
        self.analyseBuiltinsPerms()
        self.analyzeBackupFeatures()
        self.getNetworkConfigFile()


        # showcase parser unused features
        print("-" * 20)
        print(f"{self.parser.debuggable()=}")
        print(f"{self.parser.usesCleartextTraffic()=}")
        for e in self.parser.customPermissions():
            print(f"{e.name} | {e.permissionGroup} | {e.protectionLevel}")
        print(self.parser.exportedServices())
        '''
        print(f'{self.parser.exportedActivities()=}')
        print(f'{self.parser.exportedActivities2()=}')
        # check if both functions are the same
        print(set(self.parser.exportedActivities()) == set(self.parser.exportedActivities2()))
        print(f'{self.parser.exportedServices()=}')
        print(f'{self.parser.exportedBroadcastReceivers()=}')
        print(f'{self.parser.exportedProviders()=}')
        print(f'{self.parser.activitiesStats()=}')
        print(f'{self.parser.componentStats("provider")=}')
        print(f'{self.parser.exportedComponentStats("activity")=}')
        
