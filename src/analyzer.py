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

    '''
    def isBackupAllowed(self):
        #android:allowBackup is true for all version by default but auto back (Google drive) is true by default only from android 6
        #For apps running on and targeting Android 12 (API level 31) or higher, specifying android:allowBackup="false" does disable 
        #backups to Google Drive (auto backup), but doesn’t disable device-to-device transfers for the app.

        """
        Checks if backups are allowed.
        :return: return value used for unit tests only
        """
        # https://developer.android.com/guide/topics/manifest/application-element#allowbackup
        # is more complex than that
        self.logger.info("Analyzing backup functionnality")
        backup_attr = self.parser.allowBackup()
        #APILevel = self.parser.minSdkVersion()
        ## Not relevant to test with min sdk version because if min SDK < 23 but max > 23 auto backup is enabled anyhow
        MaxAPILevel = self.args.max_sdk_version
        backup_agent = self.parser.backupAgent()

        if backup_attr == None:
            # https://developer.android.com/guide/topics/manifest/uses-sdk-element
            # Android 6 : API level >= 23
            self.logger.info("APK allowBackup property not found! Default value is true for all Android versions (adb backup can be performed)")
            if MaxAPILevel > 23:
                self.logger.info("APK allowBackup property not found and max_sdk_version > 23. Auto backup funtionnality is activated (end-to-end encrypted Google drive backup for device running Android 9 or higher) and adb backup can be performed")
                #return None
            # otherwise default is True
            #backup_attr = True
        if backup_agent != None:
            self.logger.warning(f'App uses backup agent implemented in {backup_agent.split(".")[-1]} class. Please make deeper checks.')

        if backup_attr:
            self.logger.info("APK can be backuped (abd and auto backup).")
            return True
        self.logger.info("APK can not be backuped")
        #use this return to call self.getBackupRulesFile() in runalltests (avoid calling it if backup is prohibited)
        return False
    '''


    def isADBBackupAllowed(self):
        self.logger.info("Analyzing backup functionnality (adb)")
        backup_attr = self.parser.allowBackup()
        MaxAPILevel = self.args.max_sdk_version

        #android:allowBackup default value is true (auto backup only available for API > 23)
        if backup_attr == None and MaxAPILevel < 23:
            self.logger.info("APK allowBackup property not found! Default value is true for all Android versions (adb backup can be performed)")
            return True
        if backup_attr:
            self.logger.info("APK allowBackup property found and max_sdk_version < 23. adb backup can be performed")
            return True
        self.logger.info("APK can not be backuped with adb")
        return False



    def isAutoBackupAllowed(self):
        self.logger.info("Analyzing backup functionnality (Auto backup)")
        backup_attr = self.parser.allowBackup()
        MaxAPILevel = self.args.max_sdk_version

        #android:allowBackup default value is true (auto backup available for API > 23)
        if backup_attr == None and MaxAPILevel > 23:
            self.logger.warning("APK allowBackup property not found and max_sdk_version > 23. Auto backup funtionnality is activated (end-to-end encrypted Google drive backup for device running Android 9 or higher) and adb backup can be performed")
            return True
        if backup_attr and MaxAPILevel > 23:
            self.logger.warning("APK allowBackup property value is True and max_sdk_version > 23. Auto backup funtionnality is activated (end-to-end encrypted Google drive backup for device running Android 9 or higher) and adb backup can be performed")
            return True
        self.logger.info("APK can not be backuped with Auto Backup")
        return False
        

    def isBackupAgentImplemented(self):
        self.logger.info("Checking for own developper backup agent")
        if self.parser.backupAgent():
            self.logger.warning(f'APK implements is own backup agent in {self.parser.backupAgent().split(".")[-1]}. Please make deeper checks')
            return True
            #après cette info là on n'est pas obligé de la mettre je pense. A la fin de propose de faire une
            #fonction qui présentera l'ensemble des tests qu'on réalise au début avant de lancer le 
            #script. Ca évitera de devoir faire des else comme ça qui n'apportent rien finalement car l'évaluateur saura
            #quels tests ont été fait (et donc que s'il n'y a rien d'écrit c'est que c'est faux).
        self.logger.info("No backup agent implementation has been found")
        return False


    def getBackupRulesFile(self):
        self.logger.info("Analyzing backup functionnality")
        fullBackupContent_xml_file_rules = self.parser.fullBackupContent()
        #taking into account android 12 backup attribute dataExtractionRules
        dataExtractionRules_xml_rules_files = self.parser.dataExtractionRules()

        if fullBackupContent_xml_file_rules != None:
            self.logger.info(f'Custom rules has been defined to control what gets backed up in "{fullBackupContent_xml_file_rules}" file')
        elif dataExtractionRules_xml_rules_files != None:
            self.logger.info(f'Custom rules has been defined to control what gets backed up in "{dataExtractionRules_xml_rules_files}" file')
        else:
            self.logger.warning("fullBackupContent or dataExtractionRules properties not found. Please make a backup for further controls")

    def getNetworkConfigFile(self):
        self.logger.info("Checking existence of network_security_config XML file")
        network_security_config_xml_file = self.parser.networkSecurityConfig()

        if network_security_config_xml_file != None:
            self.logger.info(f'APK network security configuration is defined in "{network_security_config_xml_file}" file')
        else:
            self.logger.warning("networkSecurityConfig property not found")

    #Pay attention : Check the default value of exported property for services, broadcast receiver etc.
    def runAllTests(self):
        self.analyseBuiltinsPerms()
        #isBackupAllowed = self.isBackupAllowed()
        isADBBackupAllowed = self.isADBBackupAllowed()
        isAutoBackupAllowed = self.isAutoBackupAllowed()
        if isADBBackupAllowed or isAutoBackupAllowed: 
            self.getBackupRulesFile()
        self.getNetworkConfigFile()
        self.isBackupAgentImplemented()
       
       

        # showcase parser unused features
        print("-"*20)
        print(f"{self.parser.debuggable()=}")
        print(f"{self.parser.usesCleartextTraffic()=}")
        for e in self.parser.customPermissions():
            print(f"{e.name} | {e.permissionGroup} | {e.protectionLevel}")
        print(self.parser.exportedServices())
        