import xml.etree.ElementTree as ET
from .utils import (
    str2Bool,
    getResourceTypeName
)
from itertools import product


class Parser:

    def __init__(self, path):
        self.namespaces = dict([node for _, node in ET.iterparse(path, events=['start-ns'])])
        self.tree = ET.parse(path)
        self.root = self.tree.getroot()

    def _getattr(self, elm, attr):
        if ":" in attr:
            prefix, uri = attr.split(":", 1)
            attr = f"{{{self.namespaces[prefix]}}}{uri}"
        return elm.attrib.get(attr)

    def getApkInfo(self):
        from collections import namedtuple
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
        from collections import namedtuple
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
        return getResourceTypeName(self._getattr(self.root.find("application"), "android:fullBackupContent"))

    def dataExtractionRules(self):
        return getResourceTypeName(self._getattr(self.root.find("application"), "android:dataExtractionRules"))

    def networkSecurityConfig(self):
        return getResourceTypeName(self._getattr(self.root.find("application"), "android:networkSecurityConfig"))

    def getSdkVersion(self):
        """
        https://developer.android.com/guide/topics/manifest/uses-sdk-element
        if uses-sdk exists but the minSdkVersion is not set, the default value is 1
        """
        usesSdk = self.root.find("uses-sdk")
        if usesSdk != None:
            min_level = self._getattr(usesSdk, "android:minSdkVersion")
            max_level = self._getattr(usesSdk, "android:maxSdkVersion")

            if min_level is not None and max_level is not None:
                return (int(min_level),int(max_level))
            if min_level is not None:
                #if max_level does not exist return 0
                return (int(min_level),0)
            if max_level is not None:
                return (1,int(max_level))
            return (1,0)
        # if the element is not defined, we don't know
        return (0,0) # don't use None because it complexifies the code when checking for level>X

    def getNetworkSecurityConfig(self):
        # will be overwritten in the APKParser class
        return None

    def getIntentFilterExportedComponents(self):
        all_intent = {(self._getattr(e, "android:name"), e.tag) for e in self.root.findall(f'application/*/intent-filter/..')}
        not_exported = {(self._getattr(e, "android:name"), e.tag) for e in self.root.findall(f'application/*[@android:exported="false"]/intent-filter/..', namespaces=self.namespaces)}
        return all_intent-not_exported

    def getIntentFilters(self, compname):
        # get intent-filter element from a Element with given name
        intents = self.root.findall(f"application/*[@android:name=\"{compname}\"]/intent-filter", namespaces=self.namespaces)
        res = []
        # each intent on a separated line
        for e in intents:
            # an intent can have multiple actions
            names = [self._getattr(e, "android:name").split(".")[-1] for e in e.findall("action")]
            names = "\n".join(names)
            # an intent can have multiple categories
            categories = [self._getattr(e, "android:name").split(".")[-1] for e in e.findall("category")]
            categories = "\n".join(categories)
            # https://developer.android.com/training/app-links/verify-android-applinks#multi-host
            """
            All <data> elements in the same intent filter are merged together to account for all variations of their
            combined attributes. For example, the first intent filter above includes a <data> element that only declares
            the HTTPS scheme. But it is combined with the other <data> element so that the intent filter supports both
            http://www.example.com and https://www.example.com. As such, you must create separate intent filters when
            you want to define specific combinations of URI schemes and domains.
            """
            datas = e.findall("data")
            # recover all the possible attributes
            schemes = {self._getattr(e, "android:scheme") for e in datas} - {None} or {None}
            hosts = {self._getattr(e, "android:host") for e in datas} - {None} or {None}
            port = {self._getattr(e, "android:port") for e in datas} - {None} or {None}

            # path, pathPattern and pathPrefix have the same role
            path = {self._getattr(e, "android:path") for e in datas} - {None}
            pathPattern = {self._getattr(e, "android:pathPattern") for e in datas} - {None}
            pathPrefix = {self._getattr(e, "android:pathPrefix") for e in datas} - {None}
            pathPrefix = {f"{e}/.*" for e in pathPrefix} or {None} # respect syntax of pathPattern

            # put them in the same set
            path.update(pathPrefix)
            path.update(pathPattern)

            mimeType = {self._getattr(e, "android:mimeType") for e in datas} - {None} or {""}
            mimetypes = "\n".join(mimeType)

            uris = []
            # Compute all the merged combinations of data attributes
            for t in product(schemes, hosts, port, path, mimeType):
                scheme, host, port_, path_, mimeType_ = t
                # some can be None
                scheme = scheme or ""
                host = host or ""
                port_ = port_ or ""
                # Do not display ":" if port does not exist
                if port_ != "":
                    port_ = f":{port_}"
                path_ = path_ or ""
                # https://developer.android.com/guide/topics/manifest/data-element
                uri = f"{scheme}://{host}{port_}{path_}"
                # in case there are no link, don't append anything
                if uri != "://":
                    uris.append(uri)
            uris = "\n".join(uris)

            res.append([names, categories, uris, mimetypes])

        return res
