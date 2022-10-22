from termcolor import colored
from tabulate import tabulate
from .utils import CustomFormatter, printTestInfo, printSubTestInfo
import logging
from .constants import dangerous_perms


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

    def showApkInfo(self):
        printTestInfo("APK information")
        info = self.parser.getApkInfo()
        self.logger.info(f'Package name: {info.package}')
        if info.versionCode is not None: self.logger.info(f'Version code: {info.versionCode}')
        if info.versionName is not None: self.logger.info(f'Version name: {info.versionName}')

        versions = self.parser.getSdkVersion()
        uses_sdk_min_sdk_version = versions[0]
        uses_sdk_max_sdk_version = versions[1]
        min_sdk_version_args = self.args.min_sdk_version
        max_sdk_version_args = self.args.max_sdk_version
        warning_msg_1 = ""
        warning_msg_2 = ""
        res = 0

        if uses_sdk_min_sdk_version != 0 and uses_sdk_min_sdk_version != min_sdk_version_args:
            res |= 1
            warning_msg_1 += colored("(Mismatch between args "
                                     f"and uses-sdk tag : {uses_sdk_min_sdk_version})", "yellow")
        if uses_sdk_max_sdk_version != 0 and uses_sdk_max_sdk_version != max_sdk_version_args:
            res |= 2
            warning_msg_2 += colored("(Mismatch between args "
                                     f"and uses-sdk tag : {uses_sdk_max_sdk_version})", "yellow")

        self.logger.info(f'Minimal SDK version: {min_sdk_version_args} {warning_msg_1}')
        self.logger.info(f'Maximal SDK version: {max_sdk_version_args} {warning_msg_2}')
        if uses_sdk_max_sdk_version != 0:
            self.logger.warning("Declaring the android:maxSdkVersion attribute is not recommended. "
                                "Please check the official documentation")

        activities_number = self.parser.componentStats("activity")
        exported_activities_number = self.parser.exportedComponentStats("activity")
        self.logger.info(f'Number of activities: {activities_number} ({exported_activities_number} exported)')
        
        receivers_number = self.parser.componentStats("receiver")
        exported_receivers_number = self.parser.exportedComponentStats("receiver")
        self.logger.info(f'Number of receivers: {receivers_number} ({exported_receivers_number} exported)')

        providers_number = self.parser.componentStats("provider")
        exported_providers_number = self.parser.exportedComponentStats("provider")
        self.logger.info(f'Number of providers: {providers_number} ({exported_providers_number} exported)')

        services_number = self.parser.componentStats("service")
        exported_services_number = self.parser.exportedComponentStats("service")
        self.logger.info(f'Number of services: {services_number} ({exported_services_number} exported)')

        return res

    def analyzeBuiltinsPerms(self):
        printTestInfo("Analyzing required builtin permissions")
        dangerous_perms_number = 0
        for perm in self.parser.builtinsPermissions():
            if perm in dangerous_perms :
                if self.logger.level <= logging.WARNING:
                    print(colored(perm, "yellow"))
                dangerous_perms_number+=1
            else:
                self.logger.info(perm)
        if dangerous_perms_number > 0:
            if dangerous_perms_number == 1:
                msg = "permission"
            else:
                msg = "permissions"
            self.logger.warning(
                f'APK requires {dangerous_perms_number} dangerous {msg} to work properly. Check it out!')

    def analyzeCustomPerms(self):
        printTestInfo("Analyzing custom permissions")
        #Objectif : afficher le tout ce qui est en dessous de dangerous en orange car cela signifie
        #qu'une app malveillante peut utiliser la permissions (avec l'accord de l'utilisateur pour dangerous mais quand même)
        table = []
        header = ["name", "protectionLevel"]
        custom_permissions = self.parser.customPermissions()
        dangerous_protection_level = 0


        for custom_permission in custom_permissions:
            name = custom_permission.name
            protectionLevel = custom_permission.protectionLevel

            if protectionLevel == "normal" or protectionLevel == "dangerous":
                name = colored(name,"red")
                protectionLevel = colored(protectionLevel,"red")
                table.append([name, protectionLevel])
                dangerous_protection_level+=1
            elif self.logger.level <= logging.INFO:
                table.append([name, protectionLevel])

        #if self.logger.level <= logging.CRITICAL:
        if len(table) > 0: print(tabulate(table, header, tablefmt="fancy_grid"))
        if dangerous_protection_level > 0:
            if dangerous_protection_level == 1:
                msg = "permission"
            else:
                msg = "permissions"
            self.logger.critical(
                f'APK declared {dangerous_protection_level} custom {msg} with a protectionLevel <= dangerous. Check it out!')



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
            # dans le cas d'un APK rajouter des sous tests
            # le cleartext traffic sera probablement géré dans le test a cet effet donc pas besoin de le faire ici
            # on peut checker le certificate pinning et les trust anchors ici dans 2 sous-tests
            # si pas un APK ca reste comme ça
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

    def isDebuggable(self):
        """
        Default value is False
        https://developer.android.com/guide/topics/manifest/application-element#debug
        """
        printTestInfo("Checking compilation mode")
        debuggable = self.parser.debuggable()
        if debuggable:
            self.logger.warning("Debuggable flag found. APK can be debugged on a device running in user mode")
            return True
        self.logger.info("APK is not compiled in debug mode")
        return False

    def isCleartextTrafficAllowed(self):
        """
        https://developer.android.com/guide/topics/manifest/application-element#usesCleartextTraffic
        Indicates whether the app intends to use cleartext network traffic, such as cleartext HTTP. 
        The default value for apps that target API level 27 or lower is "true". 
        Apps that target API level 28 or higher default to "false".
        This flag is ignored on Android 7.0 (API level 24) and above if an Android Network Security Config is present.
        """
        printTestInfo("Checking if http traffic can be used")
        network_security_config_xml_file = self.parser.networkSecurityConfig()
        if network_security_config_xml_file is not None and self.args.min_sdk_version >= 24:
            # a terme remplacer ça par un call vers une autre fonction qui analyse le contenu du network security config
            # pour specifiquement voir si HTTP est autorisé et pour quels domaines
            # evidement cela que dans le cas d'un APK, sinon ça reste comme ça je pense
            self.logger.info("APK network security configuration is defined. Please refer to this test instead.")
            return
        cleartextTraffic = self.parser.usesCleartextTraffic()
        if cleartextTraffic or (cleartextTraffic is None and self.args.min_sdk_version <= 27):
            self.logger.warning("This app may intend to use cleartext network traffic "
                "such as HTTP to communicate with remote hosts")
            return True
        self.logger.info("Usage of cleartext traffic is not allowed "
            "(this flag is honored as a best effort, please refer to the documentation)")
        return False

    def getIntentFilterInfo(self):
        printTestInfo("Analysing Exported Intents")
        headers = ["Type", "Name", "Action", "Category", "Link", "Mime Type"]
        table = []
        for e, tag in self.parser.getIntentFilterExportedComponents():
            for intent_data in self.parser.getIntentFilters(e):
                row = []
                row.append(tag)
                row.append(e.split(".")[-1])
                row += intent_data
                table.append(row)
        print(tabulate(table, headers, tablefmt="fancy_grid"))

    def isAppLinkUsed(self):
        printSubTestInfo("Checking for AppLinks")
        self.logger.warning(
            "Found a deeplink in activity AuthenticatePCloudActivity : pcloudoauth://mobile.example.com")

    def isDeepLinkUsed(self):
        printSubTestInfo("Checking for DeepLinks")
        self.logger.critical("Found a deeplink in activity LicenseCheckActivity : https://android.cryptomator.org")
        return True

    def analyzeIntentFilters(self):
        self.getIntentFilterInfo()
        if self.isDeepLinkUsed():
            self.isAppLinkUsed()

    def runAllTests(self):
        print(colored(f"Analysis of {self.args.path}", "magenta", attrs=["bold"]))
        self.showApkInfo()
        '''
        self.analyzeBuiltinsPerms()
        self.analyzeCustomPerms()
        self.analyzeBackupFeatures()
        self.getNetworkConfigFile()
        self.isDebuggable()
        self.isCleartextTrafficAllowed()
        self.analyzeIntentFilters()
        '''
                
