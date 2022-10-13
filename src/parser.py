import xml.etree.ElementTree as ET
from .utils import str2Bool

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


    def getBackupAttr(self):
        return str2Bool(self._getattr(self.root.find("application"), "android:allowBackup"))

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

    def exportedServices(self):
        return [self._getattr(perm, "android:name") for perm in self.root.findall('application/service[@android:exported="true"]', namespaces=self.namespaces)]