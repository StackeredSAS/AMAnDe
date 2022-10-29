from termcolor import colored
from tabulate import tabulate
from .utils import (
    CustomFormatter,
    printTestInfo,
    printSubTestInfo,
    checkDigitalAssetLinks,
    runProc
)
from .config import EXTERNAL_BINARIES
import logging
from .constants import dangerous_perms
from .apkParser import APKParser


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
        if level == 0:
            self.logger.setLevel(logging.INFO)
        elif level == 1:
            self.logger.setLevel(logging.WARNING)
        elif level == 2:
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

        libraries = self.parser.usesLibrary()
        for l in libraries:
            if l is not None:
                # Default is true if not set
                req_l = l.required
                if req_l is None: req_l = True
                self.logger.info(f'Shared library "{l.name}" can be used by the application (mandatory for runtime : {req_l})')

        native_libraries = self.parser.usesNativeLibrary()
        for nl in native_libraries:
            if nl is not None:
                # Default is true if not set
                req_nl = nl.required
                if req_nl is None: req_nl = True
                self.logger.info(f'Vendor provided shared native library "{nl.name}" can be used by the application (mandatory for runtime : {req_nl})')

        features = self.parser.usesFeatures()
        for f in features:
            if f is not None:
                # Default is true if not set
                req_f = f.required
                if req_f is None: req_f = True
                self.logger.info(f'Hardware or software feature "{f.name}" can be used by the application (mandatory for runtime : {req_f})')
                
        # for now do it here
        # if we want to add post treatment we will move those kinds of checks into a new file
        if type(self.parser) is APKParser:
            cmd = EXTERNAL_BINARIES["apksigner"] + ["verify", "--print-certs", "--verbose", "--min-sdk-version",
                                                    str(self.args.min_sdk_version), self.args.path]
            cmdres = runProc(cmd)
            if cmdres:
                printSubTestInfo("Output of apksigner")
                self.logger.info(colored(f"executed command : {' '.join(cmd)}", "yellow"))
                self.logger.info(cmdres.decode())

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
        Both tag can be specified together in the Manifest
        However, for all versions equal or higher than Android 12, fullBakcupContent is override
        with datExtractionRules.
        """
        printSubTestInfo("Checking backup rules files")
        fullBackupContent_xml_file_rules = self.parser.fullBackupContent()
        # taking into account android 12 backup attribute dataExtractionRules
        dataExtractionRules_xml_rules_files = self.parser.dataExtractionRules()

        res = 0
        if self.args.min_sdk_version <= 30:
            if fullBackupContent_xml_file_rules is not None:
                self.logger.info(f'For Android versions <= 11 (API 30), custom rules has been defined to control what gets backed up in {fullBackupContent_xml_file_rules} file')
                res |= 1
            else:
                self.logger.warning(f'Minimal supported SDK version ({self.args.min_sdk_version})'
                f' allows Android versions <= 11 (API 30) and no exclusion custom rules file has been specified in the fullBackupContent attribute.')
        if self.args.max_sdk_version >= 31:
            if dataExtractionRules_xml_rules_files is not None:
                self.logger.info(f'For Android versions >= 12 (API 31), custom rules has been defined to control what gets backed up in {dataExtractionRules_xml_rules_files} file')
                res |= 2
            else:
                self.logger.warning(f'Maximal supported SDK version ({self.args.max_sdk_version})'
                f' allows Android versions >= 12 (API 31) and no exclusion custom rules file has been specified in the dataExtractionRules attribute.')
        return res

    def getNetworkConfigFile(self):
        printTestInfo("Checking the existence of network_security_config XML file")
        network_security_config_xml_file = self.parser.networkSecurityConfig()
        if network_security_config_xml_file is not None:
            # dans le cas d'un APK rajouter des sous tests
            # le cleartext traffic sera probablement géré dans le test a cet effet donc pas besoin de le faire ici
            # on peut checker le certificate pinning et les trust anchors ici dans 2 sous-tests
            # si pas un APK ca reste comme ça
            self.logger.info(f'APK network security configuration is defined in {network_security_config_xml_file} file')
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
    
    def analyzeExportedComponent(self):
        """
        Analyzing exported components permissions
        1. If exported component don't specifiy any permission -> self.logger.warning to make deeper check
            If it's a deeplink or applink -> it can not have specific perm because by default is used to call our app when
            a specific uri is handled by another app
        """
        printTestInfo("Checking if exported components required special permission to be called")
        headers = ["Name", "Type", "Permission", "readPermission", "writePermission"]
        table = []
        # Getting deeplink (don't analyze exported component which is a deeplink)
        universal_links = self.parser.getUniversalLinks()
        # Getting a set of deeplink components' name
        unique_names = {universal_link.name for universal_link in universal_links}
        count = 0
        res = 0

        for component in ["activity", "receiver", "provider", "service"]:
            for e in self.parser.getExportedComponentPermission(component):
                #print(e)
                if e.componentName not in unique_names:
                    n = e.componentName.split(".")[-1]
                    t = e.componentType
                    p = e.permission
                    # Keep entire permission name to make the difference between custom and builtin
                    rp = e.readPermission
                    wp = e.writePermission

                    if (t != "provider" and p is None) or (
                        t == "provider" and wp is None and rp is None and p is None):
                        cName = colored(n, "yellow")
                        cType = colored(t, "yellow")
                        table.append([cName, cType, p, rp, wp])
                        count += 1
                        res += 1
                    else:
                        table.append([n, t, p, rp, wp])
                        res += 2
        
        # There might not be any exported components -> no permission to analyze
        if len (table) > 0 :
            # no write permissions
            nowp = all([e[-1] == None for e in table])
            # no read permissions
            norp = all([e[-2] == None for e in table])
            # remove empty columns
            # start with the inner most column otherwise the index changes
            if norp:
                table = [e[:-2]+e[-1:] for e in table]
                headers.pop(-2)
            if nowp:
                table = [e[:-1] for e in table]
                headers.pop(-1)

            print(tabulate(table, headers, tablefmt="fancy_grid"))
        if count > 0:
            self.logger.warning(f'There are {count} exported components which can be called wihtout any permission. Check it out!')
        return res

    def analyzeUnexportedProviders(self):
        printTestInfo("Analyzing unexported providers")
        res = self.parser.getUnexportedProviders()
        msg = ""
        if len(res) == 1: msg = "provider"
        if len(res) > 1: msg = "providers"
        if len(res) > 0:
            self.logger.warning(f'Found {len(res)} unexported {msg} with grantUriPermissions set to True. Please make deeper checks!')
        if self.logger.level <= logging.WARNING:
            for e in res:
                print(f'\t{e}')

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
        headers = ["Name", "Action", "Category", "Link", "Mime Type"]
        table = []
        for e, tag in self.parser.getIntentFilterExportedComponents():
            for intent_data in self.parser.getIntentFilters(e):
                row = []
                row.append(f'{e.split(".")[-1]}\n({tag})')
                row += intent_data
                table.append(row)
        if len(table) > 0:
            self.logger.info(tabulate(table, headers, tablefmt="fancy_grid"))

    def isAppLinkUsed(self):
        printSubTestInfo("Checking for AppLinks")
        res = self.parser.getUniversalLinks()
        verified_hosts = {h for e in res if e.autoVerify for h in e.hosts}

        for host in verified_hosts:
            # check if the assetlink.json is publicly accessible
            active_msg = colored("Digital Asset Link JSON file not found", "red")
            if checkDigitalAssetLinks(host):
                active_msg = colored(f"Digital Asset Link JSON file found at https://{host}/.well-known/assetlinks.json", "green")
            self.logger.warning(f'Found an applink with host "{host}":')
            if self.logger.level <= logging.WARNING:
                print(active_msg)

            # only applink infos for this particular host
            applinks = [e for e in res if host in e.hosts]
            # might be used in multiple activities
            unique_names = {a.name for a in applinks}
            # separate by activities
            for name in unique_names:
                # only applink infos for this particular host and for this activity
                applinks_with_this_name = [e for e in applinks if e.name == name]
                if self.logger.level <= logging.WARNING:
                    print(colored(f'\tDeclared in {applinks_with_this_name[0].tag} {name.split(".")[-1]} '
                              f'with the following URI :', "yellow"))
                    # show the URI
                    for applink in applinks_with_this_name:
                        for uri in applink.uris:
                            print(f"\t\t{uri}")
        return len(verified_hosts)

    def isDeepLinkUsed(self):
        printSubTestInfo("Checking for DeepLinks")
        res = self.parser.getUniversalLinks()
        unique_names = {deeplink.name for deeplink in res}
        # get component name and uris
        for name in unique_names:
            deeplinks = [e for e in res if e.name == name]
            self.logger.warning(f'Found a deeplink in {deeplinks[0].tag} {deeplinks[0].name.split(".")[-1]}'
                                f'with the following URI:')
            for deeplink in deeplinks:
                for uri in deeplink.uris:
                    if self.logger.level <= logging.WARNING:
                        print(f"\t{uri}")
        return len(unique_names) > 0

    def analyzeIntentFilters(self):
        self.getIntentFilterInfo()
        if self.isDeepLinkUsed():
            self.isAppLinkUsed()

    def runAllTests(self):
        print(colored(f"Analysis of {self.args.path}", "magenta", attrs=["bold"]))
        self.showApkInfo()
        self.analyzeBuiltinsPerms()
        self.analyzeCustomPerms()
        self.analyzeBackupFeatures()
        self.getNetworkConfigFile()
        self.isDebuggable()
        self.isCleartextTrafficAllowed()
        self.analyzeIntentFilters()
        self.analyzeExportedComponent()
        self.analyzeUnexportedProviders()
