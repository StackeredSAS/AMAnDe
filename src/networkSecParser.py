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
        # todo : remove this function when done implementing the analyzer
        self.path.seek(0)
        print(self.path.read())

    def parseCertificate(self, elm, default=False):
        """
        Parses the <certificate> element.
        The default argument is used to specify the default value for the overridePins attribute.
        It is False by default unless specified in a <debug-overrides> element.
        https://developer.android.com/training/articles/security-config?hl=en#certificates
        """
        cert = namedtuple("Cert", "src overridePins")
        src = self._getattr(elm, "src")
        overridePins = str2Bool(self._getattr(elm, "overridePins"))
        if overridePins is None:
            overridePins = default
        return cert(src, overridePins)

    def parseTrustAnchors(self, elm, default=False):
        """
        Parses the <trust-anchors> elements of the specified parent.
        Returns a list of all the certificates' information.
        The default argument is used to specify the default value for the overridePins attribute
        of the child <certificate> elements.
        It is False by default unless specified in a <debug-overrides> element.
        https://developer.android.com/training/articles/security-config?hl=en#trust-anchors
        """
        certs = elm.findall("trust-anchors/certificates")
        return [self.parseCertificate(e, default) for e in certs]

    def getBaseConfig(self):
        """
        Parses the <base-config> element of the network security config file.
        https://developer.android.com/training/articles/security-config?hl=en#base-config
        Default values are API level dependant.
        """
        config = namedtuple("BConfig", "cleartextTrafficPermitted trustanchors")
        bc = self.root.find("base-config")
        if bc is not None:
            cleartextTrafficPermitted = str2Bool(self._getattr(bc, "cleartextTrafficPermitted"))
            trustanchors = self.parseTrustAnchors(bc)
            return config(cleartextTrafficPermitted, trustanchors)

    def getDebugOverrides(self):
        """
        Parses the <debug-overrides> element of the network security config file.
        https://developer.android.com/training/articles/security-config?hl=en#debug-overrides
        """
        bc = self.root.find("debug-overrides")
        if bc is not None:
            return self.parseTrustAnchors(bc, True)

    def parsePinSet(self, elm):
        """
        Parses the <pin-set> elements of the specified parent.
        https://developer.android.com/training/articles/security-config?hl=en#pin-set
        Only the expiration attribute is interesting in our case.
        """
        ps = elm.find("pin-set")
        if ps is not None:
            return self._getattr(ps, "expiration")

    def parseDomains(self, elm):
        """
        Parses the <domain> elements of the specified parent.
        https://developer.android.com/training/articles/security-config?hl=en#domain
        If the includeSubdomains attribute is True, the domain will be prefixed with "*.".
        """
        res = []
        for e in elm.findall("domain"):
            includeSubdomains = str2Bool(self._getattr(e, "includeSubdomains"))
            domain = e.text
            if includeSubdomains:
                domain = f"*.{domain}"
            res.append(domain)
        return res

    def parseDomainConfig(self, elm=None):
        """
        Recursively parses the <domain-config> elements of the specified parent.
        https://developer.android.com/training/articles/security-config?hl=en#domain-config
        Any number of nested <domain-config> elements can be present.
        """
        if elm is None:
            elm = self.root
        config = namedtuple("DConfig", "cleartextTrafficPermitted domains trustanchors pinset domainConfigs")
        dc = elm.findall("domain-config")
        res = []
        for e in dc:
            cleartextTrafficPermitted = str2Bool(self._getattr(e, "cleartextTrafficPermitted"))
            domains = self.parseDomains(e)
            trustanchors = self.parseTrustAnchors(e)
            pinset = self.parsePinSet(e)
            # recursive call to handle nested <domain-config> elements
            dcs = self.parseDomainConfig(e)
            res.append(config(cleartextTrafficPermitted, domains, trustanchors, pinset, dcs))
        return res


    def getAllDomains(self, dcs=None, inheritedCT=False, withCT=True):
        """
        Recursively lists all the domains with cleartext traffic allowed or not.
        Takes into consideration the inheriting properties of the parent.
        """
        if dcs is None:
            dcs = self.parseDomainConfig()
        res = []
        for dc in dcs:
            if dc.cleartextTrafficPermitted == withCT:
                res += dc.domains
            if dc.cleartextTrafficPermitted is None and not (inheritedCT ^ withCT):
                res += dc.domains
            # recursive call with inherited value
            if dc.cleartextTrafficPermitted is not None:
                # parent defined cleartextTrafficPermitted
                res += self.getAllDomains(dc.domainConfigs, dc.cleartextTrafficPermitted, withCT=withCT)
            else:
                # parent did not define cleartextTrafficPermitted
                # use parent inherited value
                res += self.getAllDomains(dc.domainConfigs, inheritedCT, withCT=withCT)
        return res

    def getDomainsWithTA(self, dcs=None, inheritedTA=False):
        """
        Recursively lists all the domains with their associated trust-anchors.
        Takes into consideration the inheriting properties of the parent.
        """
        if dcs is None:
            dcs = self.parseDomainConfig()
        domainConf = namedtuple("DomainConf", "domain, trustanchors")
        res = []
        for dc in dcs:
            if len(dc.trustanchors) > 0:
                # add all domains of this domain config with the defined TA
                res += [domainConf(e, dc.trustanchors) for e in dc.domains]
                # recursive call with defined TA
                res += self.getDomainsWithTA(dc.domainConfigs, dc.trustanchors)
            else:
                # add all domains of this domain config with the inherited TA
                res += [domainConf(e, inheritedTA) for e in dc.domains]
                # recursive call with the inherited TA
                res += self.getDomainsWithTA(dc.domainConfigs, inheritedTA)
        return res