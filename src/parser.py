import xml.etree.ElementTree as ET
from .utils import (
    str2Bool,
    getResourceTypeName
)
from itertools import product
from termcolor import colored
from collections import namedtuple


class Parser:

    def __init__(self, path):
        self.namespaces = dict([node for _, node in ET.iterparse(path, events=['start-ns'])])
        self.tree = ET.parse(path)
        self.root = self.tree.getroot()
        self.apk = None

    def _getattr(self, elm, attr):
        if ":" in attr:
            prefix, uri = attr.split(":", 1)
            attr = f"{{{self.namespaces[prefix]}}}{uri}"
        res = elm.attrib.get(attr)
        if res and res.startswith("@"):
            # resource
            path, name = getResourceTypeName(res)
            res = self._getResValue(path, name)
        return res

    def _getResValue(self, path, name):
        filename = path.split("/")[-1]
        res = colored(f"{filename}", attrs=["underline"])
        if name:
            res = f"{res}({name})"
        return res

    def getApkInfo(self):
        # use a namedtuple for more readable access to important attributes
        Info = namedtuple("Info", "package versionCode versionName")
        package = self._getattr(self.root, "package")
        versionCode = self._getattr(self.root, "android:versionCode")
        versionName = self._getattr(self.root, "android:versionName")
        return Info(package, versionCode, versionName)

    def builtinsPermissions(self):
        """
        récupère les builtins permissions
        :return:
        """
        return [self._getattr(perm, "android:name") for perm in self.root.findall('uses-permission')]

    def allowBackup(self):
        return str2Bool(self._getattr(self.root.find("application"), "android:allowBackup"))

    def backupAgent(self):
        return self._getattr(self.root.find("application"), "android:backupAgent")

    def debuggable(self):
        return str2Bool(self._getattr(self.root.find("application"), "android:debuggable"))

    def usesCleartextTraffic(self):
        return str2Bool(self._getattr(self.root.find("application"), "android:usesCleartextTraffic"))

    def customPermissions(self):
        # use a namedtuple for more readable access to important attributes
        CustomPerm = namedtuple("CustomPerm", "name protectionLevel")
        res = []
        for perm in self.root.findall('permission'):
            name = self._getattr(perm, "android:name")
            protectionLevel = self._getattr(perm, "android:protectionLevel")
            res.append(CustomPerm(name, protectionLevel))
        return res

    def exportedComponents(self, component):
        """
        For all components, android:exported is false since Android 4.2. However, 
        if this component specified an intent filter, android:exported is automatically set to True
        From Android 12, it's mandatory to specified android:exported property if a component
        contains an intent filter (False or True) -> to avoid error. Otherwise, a runtime error will be delivered.
        
        BLOG ARTICLE : https://medium.com/androiddevelopers/lets-be-explicit-about-our-intent-filters-c5dbe2dbdce0
        An important change is coming to Android 12 that improves both app and platform security. This change affects all apps that target Android 12.
        Activities, services, and broadcast receivers with declared intent-filters now must explicitly declare whether they should be exported or not.
        Prior to Android 12, components (activites, services, and broadcast receivers only) with an intent-filter declared were automatically exported
        """
        # check if there is android:exported property set to True (no matter intent filter)
        exported_component = {self._getattr(e, "android:name") for e in self.root.findall(f'application/{component}[@android:exported="true"]', namespaces=self.namespaces)}
        # check if there is an intent filter in component tag
        intent_component = {self._getattr(e, "android:name") for e in self.root.findall(f'application/{component}/intent-filter/..', namespaces=self.namespaces)}
        # check if there is android:exported property set to False (no matter intent filter)
        unexported_component = {self._getattr(e, "android:name") for e in self.root.findall(f'application/{component}[@android:exported="false"]', namespaces=self.namespaces)}
        # update components (if there is android:exported to False and intent-filter, component is not exported)
        exported_component.update(intent_component - unexported_component)
        return list(exported_component)

    def componentStats(self, component):
        return len(self.root.findall(f'application/{component}'))

    def exportedComponentStats(self, component):
        return len(self.exportedComponents(component))

    def fullBackupContent(self):
        return self._getattr(self.root.find("application"), "android:fullBackupContent")

    def dataExtractionRules(self):
        return self._getattr(self.root.find("application"), "android:dataExtractionRules")

    def networkSecurityConfig(self):
        return self._getattr(self.root.find("application"), "android:networkSecurityConfig")

    def getSdkVersion(self):
        """
        https://developer.android.com/guide/topics/manifest/uses-sdk-element
        if uses-sdk exists but the minSdkVersion is not set, the default value is 1
        """
        usesSdk = self.root.find("uses-sdk")
        # if not defined return 0
        min_level = 0
        max_level = 0
        if usesSdk is not None:
            min_level = int(self._getattr(usesSdk, "android:minSdkVersion") or 1)
            # if max_level does not exist return 0
            max_level = int(self._getattr(usesSdk, "android:maxSdkVersion") or 0)
        return min_level, max_level

    def getNetworkSecurityConfig(self):
        # will be overwritten in the APKParser class
        return None

    def getExportedComponentPermission(self, componentType):
        """
        https://developer.android.com/guide/topics/manifest/<component>-element
        From a list of all exported components, check if component requires specific permission
        to be called
        PROVIDER: android:permission, android:grantUriPermissions, android:readPermission, android:writePermission 
        The name of a permission that clients must have to read or write the content provider's data. 
        This attribute is a convenient way of setting a single permission for both reading and writing. 
        However, the readPermission, writePermission, and grantUriPermissions (False by default) attributes take precedence 
        over this one.
        ACTIVITY, SERVICE, RECEIVER: android:permission

        Return a list of namedTuple
        """

        # use a namedtuple for more readable access to important attributes
        ExportedComponents = namedtuple("exportedComponents", "componentName, componentType permission readPermission writePermission grantUriPermissions")
        res = []
        for name in self.exportedComponents(componentType):
            component = self.root.find(f'application/{componentType}[@android:name="{name}"]', namespaces=self.namespaces)
            permission = self._getattr(component, "android:permission")
            readPermission, writePermission, grantUriPermissions = None, None, None
            if (componentType == "provider"):
                readPermission = self._getattr(component, "android:readPermission")
                writePermission = self._getattr(component, "android:writePermission")
                grantUriPermissions = str2Bool(self._getattr(component, "android:grantUriPermissions"))
            res.append(ExportedComponents(name, componentType, permission, readPermission, writePermission, grantUriPermissions))
        return res
       
    def getIntentFilterExportedComponents(self):
        """
        Return tuple (componentName, componentType) for each exported component having 
        one or more intent_filter(s) (android:exported is true or none)
        """
        all_intent = {(self._getattr(e, "android:name"), e.tag) for e in self.root.findall(f'application/*/intent-filter/..')}
        not_exported = {(self._getattr(e, "android:name"), e.tag) for e in self.root.findall(f'application/*[@android:exported="false"]/intent-filter/..', namespaces=self.namespaces)}
        return all_intent-not_exported

    def getIntentFilters(self, compname):
        # get intent-filter element from a Element with given name
        """
        Return a list containing intent_filters information (action, category, data_uris, mimetypes) 
        from an Element with given name
        """
        intents = self.root.findall(f"application/*[@android:name=\"{compname}\"]/intent-filter", namespaces=self.namespaces)
        res = []
        # each intent on a separated line
        for e in intents:
            # an intent can have multiple actions
            actions = [self._getattr(e, "android:name").split(".")[-1] for e in e.findall("action")]
            actions = "\n".join(actions)
            # an intent can have multiple categories
            categories = [self._getattr(e, "android:name").split(".")[-1] for e in e.findall("category")]
            categories = "\n".join(categories)
            mimeType = {self._getattr(e, "android:mimeType") for e in e.findall("data")} - {None} or {""}
            mimetypes = "\n".join(mimeType)

            # Compute all the merged combinations of data attributes
            # https://developer.android.com/guide/topics/manifest/data-element
            uris = self._getIntentFiltersUrisInfo(e)
            uris = "\n".join(uris)

            res.append([actions, categories, uris, mimetypes])

        return res

    def _getIntentFiltersUrisInfo(self, intent):
        # https://developer.android.com/training/app-links/verify-android-applinks#multi-host
        """
        All <data> elements in the same intent filter are merged together to account for all variations of their
        combined attributes. For example, the first intent filter above includes a <data> element that only declares
        the HTTPS scheme. But it is combined with the other <data> element so that the intent filter supports both
        http://www.example.com and https://www.example.com. As such, you must create separate intent filters when
        you want to define specific combinations of URI schemes and domains.
        """
        datas = intent.findall("data")
        # recover all the possible attributes
        schemes = {self._getattr(e, "android:scheme") for e in datas} - {None}
        schemes = {f"{e}://" for e in schemes} or {""}
        hosts = {self._getattr(e, "android:host") for e in datas} - {None} or {""}
        port = {self._getattr(e, "android:port") for e in datas} - {None}
        port = {f":{e}" for e in port} or {""}

        # path, pathPattern and pathPrefix have the same role
        path = {self._getattr(e, "android:path") for e in datas} - {None}
        pathPattern = {self._getattr(e, "android:pathPattern") for e in datas} - {None}
        pathPrefix = {self._getattr(e, "android:pathPrefix") for e in datas} - {None}
        pathPrefix = {f"{e}/.*" for e in pathPrefix} or {""}  # respect syntax of pathPattern
        # put them in the same set
        path.update(pathPrefix)
        path.update(pathPattern)

        # Compute all the merged combinations of data attributes
        # https://developer.android.com/guide/topics/manifest/data-element
        return ["".join(uri) for uri in product(schemes, hosts, port, path)]

    def getUniversalLinks(self):
        # do not keep the tag
        exported_components = self.getIntentFilterExportedComponents()
        # use a namedtuple for more readable access to important attributes
        UniversalLink = namedtuple("UniversalLink", "name tag autoVerify uris hosts")
        deepLinks = []
        for compname, tag in exported_components:
            # https://developer.android.com/training/app-links/deep-linking
            # deep links must have ACTION_VIEW
            intents = self.root.findall(f'application/*[@android:name=\"{compname}\"]/intent-filter/action[@android:name="android.intent.action.VIEW"]/..', namespaces=self.namespaces)
            for i in intents:
                # deep links must have category BROWSABLE
                if i.find('category[@android:name="android.intent.category.BROWSABLE"]', namespaces=self.namespaces) is not None:
                    uris = self._getIntentFiltersUrisInfo(i)
                    # add additional info to check if a deeplink is actually an app link
                    hosts = {self._getattr(e, "android:host") for e in i.findall("data")} - {None} or {""}
                    autoVerify = str2Bool(self._getattr(i, "android:autoVerify"))
                    deepLinks.append(UniversalLink(compname, tag, autoVerify, uris, hosts))

        return deepLinks

    def getFullBackupContentRules(self):
        # will be overwritten in the APKParser class
        return None

    def getDataExtractionRulesContent(self):
        # will be overwritten in the APKParser class
        return None