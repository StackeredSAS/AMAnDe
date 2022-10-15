from termcolor import colored
from tabulate import tabulate
from .utils import CustomFormatter
import logging
from .constants import *

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
            if perm in dangerous_perms:
                perm = colored(perm, "red")

            table.append([perm])
        self.logger.info(tabulate(table, header, tablefmt="github"))
        # ajouter la logique
        self.logger.error(f"Found vulnerable perms : android.permission.ACCESS_NETWORK_STATE")


    def isBackupAllowed(self):
        """
        Checks if backups are allowed.
        :return: return value used for unit tests only
        """
        # https://developer.android.com/guide/topics/manifest/application-element#allowbackup
        # is more complex than that
        self.logger.info("Analyzing backup functionnality")
        backup_attr = self.parser.allowBackup()
        APILevel = self.parser.minSdkVersion()

        ##ICi je comptais d'abord faire un check de ce style :
        #pour vérifier que la balise <uses-sdk> est utilisée et que l'attribut minsdkversion a été défini
        #if APILevel != 0 and APILevel > 1
        if backup_attr == None:
            # https://developer.android.com/guide/topics/manifest/uses-sdk-element
            # Android 6 : API level >= 23
            if APILevel < 23:
                self.logger.info("APK allowBackup property not found! From Android 6 (API level 23), the default value is true.")
                return None
            # otherwise default is True
            backup_attr = True
        if backup_attr:
            self.logger.info("APK can be backuped.")
            return True
        self.logger.info("APK can not be backuped")
        return False
        #et faire un else ici pour si jamais ce n'est pas défini de faire les checks avec les args passés
        #en ligne de commande. PArce que sinon si le uses-sdk existe pas les tests seront moins pertinents
        
    def getBackupRulesFile(self):
        self.logger.info("Analyzing backup functionnality")
        backup_content_xml_file_rules = self.parser.fullBackupContent()

        if backup_content_xml_file_rules != None:
            self.logger.info(f'Custom rules has been defined to control what gets backed up in "{backup_content_xml_file_rules}" file')
        else:
            self.logger.warning("fullBackupContent property not found. Please make a backup for further controls")

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
        self.isBackupAllowed()
        self.getBackupRulesFile()
        self.getNetworkConfigFile()
       

        # showcase parser unused features
        print("-"*20)
        print(f"{self.parser.debuggable()=}")
        print(f"{self.parser.usesCleartextTraffic()=}")
        for e in self.parser.customPermissions():
            print(f"{e.name} | {e.permissionGroup} | {e.protectionLevel}")
        print(self.parser.exportedServices())
        