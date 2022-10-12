import xml.etree.ElementTree as ET

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

    def builtinsPermission(self):
        """
        récupère les builtins permissions
        :return:
        """
        return [self._getattr(perm, "android:name") for perm in self.root.findall('uses-permission')]