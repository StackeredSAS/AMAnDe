import xml.etree.ElementTree as ET
from .utils import (
    str2Bool,
    getResourceTypeName
)

class Parser():

    def __init__(self, path):
        self.namespaces = dict([node for _, node in ET.iterparse(path, events=['start-ns'])])
        self.tree = ET.parse(path)
        self.root = self.tree.getroot()

    def _getattr(self, elm, attr):
        if ":" in attr:
            prefix, uri = attr.split(":", 1)
            attr = f"{{{self.namespaces[prefix]}}}{uri}"
        return elm.attrib.get(attr)


    def builtinsPermissions(self):
        """
        récupère les builtins permissions
        :return:
        """
        return [self._getattr(perm, "android:name") for perm in self.root.findall('uses-permission')]

    #BACKUP 
    def allowBackup(self):
        return str2Bool(self._getattr(self.root.find("application"), "android:allowBackup"))

    def backupAgent(self):
        return self._getattr(self.root.find("application"), "android:backupAgent")

    def debuggable(self):
        return str2Bool(self._getattr(self.root.find("application"), "android:debuggable"))

    def usesCleartextTraffic(self):
        return str2Bool(self._getattr(self.root.find("application"), "android:usesCleartextTraffic"))

    def customPermissions(self):
        """
        J'ai pas encore décidé si cette fonction doit juste renvoyer le nom des customPerms
        et faire une fonction différente appellant celle-ci pour récupérer des attributs particuliers.
        Comme-ça ca me semble bien.
        J'y réfléchirai sérieusement quand on fera le parsing des activité, là c'est plus complexe.
        """
        from collections import namedtuple
        # use a namedtuple for more readable access to important attributes
        CustomPerm = namedtuple("CustomPerm", "name permissionGroup protectionLevel")
        res = []
        for perm in self.root.findall('permission'):
            name = self._getattr(perm, "android:name")
            # not sure if permission group is important or not
            permissionGroup = self._getattr(perm, "android:permissionGroup")
            protectionLevel = self._getattr(perm, "android:protectionLevel")
            res.append(CustomPerm(name, permissionGroup, protectionLevel))
        return res



    
    '''
    For all components, android:exported is false since Android 4.2. However, 
    if this component specified an intent filter, android:exported is automatically set to True
    From Android 12, it's mandatory to specified android:exported property if a component
    contains an intent filter (False or True) -> to avoid error. Otherwise, a runtime error will be delivered.
    
    BLOG ARTICLE : https://medium.com/androiddevelopers/lets-be-explicit-about-our-intent-filters-c5dbe2dbdce0
    An important change is coming to Android 12 that improves both app and platform security. This change affects all apps that target Android 12.
    Activities, services, and broadcast receivers with declared intent-filters now must explicitly declare whether they should be exported or not.
    Prior to Android 12, components (activites, services, and broadcast receivers only) with an intent-filter declared were automatically exported
    '''

    def exportedComponents(self, component):
        #check if there is android:exported property set to True (no matter intent filter)
        exported_component = {self._getattr(e, "android:name") for e in self.root.findall(f'application/{component}[@android:exported="true"]', namespaces=self.namespaces)}
        #check if there an intent filter in component tag
        intent_component = {self._getattr(e, "android:name") for e in self.root.findall(f'application/{component}/intent-filter/..', namespaces=self.namespaces)}
        #check if there is android:exported property set to False (no matter intent filter)
        unexported_component = {self._getattr(e, "android:name") for e in self.root.findall(f'application/{component}[@android:exported="false"]', namespaces=self.namespaces)}
        #update components (if there android:exported to False and intent-filter, component is not exported)
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

    def minSdkVersion(self):
        usesSdk = self.root.find("uses-sdk")
        if usesSdk != None:
            level = self._getattr(usesSdk, "android:minSdkVersion")
            if level != None:
                return int(level)
            # https://developer.android.com/guide/topics/manifest/uses-sdk-element
            # if the element exists but the attribute is not set, the default value is 1
            return 1
        # if the element is not defined, we don't know
        return 0 # don't use None because it complexifies the code when checking for level>X