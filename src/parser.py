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

    #maybe change this if we want to return more than the just the name
    #Just a draft, refactor this
    def exportedActivities(self):
        exported_activities = []
        for activity in self.root.findall('application/activity'):
            exported = self._getattr(activity, "android:exported")
            name = self._getattr(activity, "android:name")
            #check if there is android:exported to true (no matter intent filter)
            if(str2Bool(exported)):
                exported_activities.append(name)
            #check if there is intent filter or both intent filter and exported to true 
            for intent_filter in activity.findall("intent-filter"):
                if (intent_filter.attrib is not None) or (intent_filter.attrib is not None and str2Bool(exported)):
                    #to not add already present activitu if there is more than one intent filter
                    exported_activities.append(name) if name not in exported_activities else None
        return exported_activities

    def exportedActivities2(self):
        exported_activities = {self._getattr(e, "android:name") for e in self.root.findall('application/activity[@android:exported="true"]', namespaces=self.namespaces)}
        intent_activities = {self._getattr(e, "android:name") for e in self.root.findall('application/activity/intent-filter/..', namespaces=self.namespaces)}
        unexported_activities = {self._getattr(e, "android:name") for e in self.root.findall('application/activity[@android:exported="false"]', namespaces=self.namespaces)}
        exported_activities.update(intent_activities-unexported_activities)
        return list(exported_activities)

    #when exportedActivities will be okay, it can be the same intelligence for all components
    def exportedServices(self):
        return [self._getattr(e, "android:name") for e in self.root.findall('application/service[@android:exported="true"]', namespaces=self.namespaces)]

    def exportedBroadcastReceivers(self):
        return [self._getattr(e, "android:name") for e in self.root.findall('application/receiver[@android:exported="true"]', namespaces=self.namespaces)]

    def exportedProviders(self):
        return [self._getattr(e, "android:name") for e in self.root.findall('application/provider[@android:exported="true"]', namespaces=self.namespaces)]

    #soit on fait une fonction pour chaque
    def activitiesStats(self):
        return sum(1 for perm in self.root.findall('application/activity'))

    #soit une fonction générique comme ci-dessous
    #Displaying stats about components (how many of each are declared)
    def componentStats(self, component):
        return sum(1 for perm in self.root.findall(f'application/{component}'))

    def exportedComponentStats(self, component):
        return sum(1 for perm in self.root.findall(f'application/{component}[@android:exported="true"]' ,namespaces=self.namespaces)) if component in ["activity", "provider", "receiver", "service"] else None

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