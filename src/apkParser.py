from .parser import Parser
from zipfile import ZipFile, BadZipfile
from pyaxmlparser.axmlprinter import AXMLPrinter
from pyaxmlparser.arscparser import ARSCParser
import xml.etree.ElementTree as ET
import re
from .constants import protection_levels
# for virtual file handling in case of APK
from io import StringIO
from .utils import unformatFilename

class APKParser(Parser):

    def __init__(self, path):
        try:
            # Unzip the APK
            self.apk = ZipFile(path)
            # Does not always have a resource file so this might be None
            self.rsc = self._getApkFileContent("resources.arsc")
            if self.rsc is not None:
                self.rsc = ARSCParser(self.rsc)
            # this can change self.apk to None if there is no manifest in the ZIP file
            self._loadManifest()
        except BadZipfile:
            self.apk = None

    def _getApkFileContent(self, path):
        # the pythonic way of checking if a file exists
        try:
            return self.apk.open(path, "r").read()
        except KeyError:
            pass

    def _getResource(self, rid, package_name=None):
        """
        Transforms an ID of the form @7F0A01BF into @xml/network_security_config.
        :param rid: the ID
        :param package_name: The package name
        :return: The resource path
        """
        if self.rsc is None:
            # if there is no resources.arsc we can't do anything
            # this should never happen tho
            return rid
        if package_name is None:
            # I don't know how to handle the case when there are multiple package names yet
            package_name = self.rsc.get_packages_names()[0]
        rid = int(rid.strip("@"), 16)
        res_type, name, _ = self.rsc.get_id(package_name, rid)
        if res_type == "string":
            # index 0 is name, index 1 is the resolved string
            return self.rsc.get_string(package_name, name)[1]
        return f"@{res_type}/{name}"

    def _getCleanXML(self, path):
        """
        Transform an AXML converted XML file into something more closer to the original XML.
        All resource IDs are replaced with their original value.
        """
        file_content = self._getApkFileContent(path)
        if file_content is None:
            return
        bad_xml = AXMLPrinter(self.apk.open(path, "r").read()).get_xml().decode()
        # find all @XXXXXXXX resource IDs
        rsc_ids = set(re.findall(r"(@[0-9A-F]{8})", bad_xml))
        for rid in rsc_ids:
            # replace the IDs with the correct resource name
            bad_xml = bad_xml.replace(rid, self._getResource(rid))
        return StringIO(bad_xml)

    def _loadManifest(self):
        """
        Initializes the manifest's tree and root objects and loads the namespaces.
        """
        path = self._getCleanXML("AndroidManifest.xml")
        if path is None:
            # this means we don't have a valid APK but a simple ZIP file
            # error will propagate
            self.apk = None
            return
        # here we have a clean manifest in a virtual file
        self.namespaces = dict([node for _, node in ET.iterparse(path, events=['start-ns'])])
        # because it's the same file object, we have to rewind to the beginning before parsing again
        path.seek(0)
        self.tree = ET.parse(path)
        self.root = self.tree.getroot()

    def customPermissions(self):
        """
        In the case of APK custom permission protection level is an Int.
        """
        from collections import namedtuple
        # use a namedtuple for more readable access to important attributes
        CustomPerm = namedtuple("CustomPerm", "name protectionLevel")
        res = []
        for perm in self.root.findall('permission'):
            name = self._getattr(perm, "android:name")
            # Get the protection level name from its enum value
            protectionLevel = int(self._getattr(perm, "android:protectionLevel"), 16)
            protectionLevel = protection_levels[protectionLevel]
            res.append(CustomPerm(name, protectionLevel))
        return res

    def _realPathFromTypeAndName(self, resType, name, package_name=None):
        if package_name is None:
            # I don't know how to handle the case when there are multiple package names yet
            package_name = self.rsc.get_packages_names()[0]
        # recover the rid from the resource type and filename
        rid = self.rsc.resource_keys[package_name][resType][name]
        # get_res_configs returns a list of tuples
        # we only care about the first element of this list
        # and the second element of the tuple is a ARSCResTableEntry
        # https://github.com/appknox/pyaxmlparser/blob/d111a4fc6330a0c293ffc2f114af360eb78ad2ef/pyaxmlparser/arscutil.py#L509
        # the key attribute holds a ARSCResStringPoolRef
        # https://github.com/appknox/pyaxmlparser/blob/d111a4fc6330a0c293ffc2f114af360eb78ad2ef/pyaxmlparser/arscutil.py#L580
        # the get_data_value function gives us what we are looking for
        real_path = self.rsc.get_res_configs(rid)[0][1].key.get_data_value()
        return real_path

    def getNetworkSecurityConfig(self):
        """
        Example de truc qu'on peut faire propre aux APK.
        """
        filename = self.networkSecurityConfig()
        if filename is None:
            return
        # filename is fucked up because of the color and the stuff done in getResourceTypeName
        path = self._realPathFromTypeAndName("xml", unformatFilename(filename).split(".")[0])
        return self._getCleanXML(path).read()

