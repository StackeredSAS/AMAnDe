from .parser import Parser
import xml.etree.ElementTree as ET
from collections import namedtuple
from .utils import str2Bool

class NetworkSecParser(Parser):

    def __init__(self, path):
        # here we have a clean manifest in a virtual file
        self.path = path
        self.namespaces = dict([node for _, node in ET.iterparse(path, events=['start-ns'])])
        # because it's the same file object, we have to rewind to the beginning before parsing again
        path.seek(0)
        self.tree = ET.parse(path)
        self.root = self.tree.getroot()

    def printXML(self):
        self.path.seek(0)
        print(self.path.read())

    def parseCertificate(self, elm, default=False):
        cert = namedtuple("Cert", "src overridePins")
        src = self._getattr(elm, "src")
        overridePins = str2Bool(self._getattr(elm, "overridePins"))
        if overridePins is None:
            overridePins = default
        return cert(src, overridePins)

    def parseTrustAnchors(self, elm, default=False):
        certs = elm.findall("trust-anchors/certificates")
        return [self.parseCertificate(e, default) for e in certs]

    def getBaseConfig(self):
        config = namedtuple("BConfig", "cleartextTrafficPermitted trustanchors")
        bc = self.root.find("base-config")
        if bc is not None:
            cleartextTrafficPermitted = str2Bool(self._getattr(bc, "cleartextTrafficPermitted"))
            trustanchors = self.parseTrustAnchors(bc)
            return config(cleartextTrafficPermitted, trustanchors)

    def getDebugOverrides(self):
        bc = self.root.find("debug-overrides")
        if bc is not None:
            return self.parseTrustAnchors(bc, True)

    def parsePinSet(self, elm):
        ps = elm.find("pin-set")
        if ps is not None:
            return self._getattr(ps, "expiration")

    def parseDomains(self, elm):
        res = []
        for e in elm.findall("domain"):
            includeSubdomains = str2Bool(self._getattr(e, "includeSubdomains"))
            domain = e.text
            if includeSubdomains:
                domain = f"*.{domain}"
            res.append(domain)
        return res

    def parseDomainConfig(self, elm=None):
        if elm is None:
            elm = self.root
        config = namedtuple("DConfig", "domains trustanchors pinset domainConfigs")
        dc = elm.findall("domain-config")
        res = []
        for e in dc:
            domains = self.parseDomains(e)
            trustanchors = self.parseTrustAnchors(e)
            pinset = self.parsePinSet(e)
            dcs = self.parseDomainConfig(e)
            res.append(config(domains, trustanchors, pinset, dcs))
        return res
