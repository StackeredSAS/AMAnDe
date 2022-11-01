#!/usr/bin/env python3
import unittest
from src.analyzer import Analyzer
from src.apkParser import APKParser
from collections import namedtuple
import logging
logging.disable(logging.CRITICAL)

class FakeParser(APKParser):
    # a fake parser class that allows init with no args
    def __init__(self):
        pass

class TestAnalyzer(unittest.TestCase):
    # We do not test the parser it is assumed the parsing is done correctly.
    # This allows much simpler unit tests writing. No need to generated custom manifests.
    parser = FakeParser()
    # fake args
    args = namedtuple("a", "log_level max_sdk_version min_sdk_version")
    args.log_level = 0
    analyzer = Analyzer(parser, args)

    def test_isADBBackupAllowed(self):
        # the tuple elements represents :
        # allowBackup, min_sdk_version, max_sdk_version, expectedResult
        testCases = [
            (True, 20, 25, True),
            (True, 20, 30, True),
            (True, 30, 31, (True, False)),
            (True, 31, 32, False),
            (False, 20, 25, False),
            (False, 20, 30, False),
            (False, 30, 31, False),
            (False, 31, 32, False),
            (None, 20, 25, True),
            (None, 20, 30, True),
            (None, 30, 31, (True, False)),
            (None, 31, 32, False),
        ]

        for testCase in testCases:
            allowBackup = testCase[0]
            min_sdk_version = testCase[1]
            max_sdk_version = testCase[2]
            expected = testCase[3]
            self.parser.allowBackup = lambda: allowBackup
            self.args.min_sdk_version = min_sdk_version
            self.args.max_sdk_version = max_sdk_version
            res = self.analyzer.isADBBackupAllowed()
            self.assertEqual(expected, res, f"{allowBackup=} and {min_sdk_version} and {max_sdk_version } should "
                                            f"produce {expected} but produced {res}")

    def test_isAutoBackupAllowed(self):
        # the tuple elements represents :
        # allowBackup, max_sdk_version, expectedResult
        testCases = [
            (True, 12, False),
            (True, 25, True),
            (True, 23, True),
            (None, 23, True),
            (None, 25, True),
            (None, 13, False),
            (False, 13, False),
            (False, 23, False),
            (False, 26, False),
        ]
        self.args.min_sdk_version = 8
        for testCase in testCases:
            allowBackup = testCase[0]
            max_sdk_version = testCase[1]
            expected = testCase[2]
            self.parser.allowBackup = lambda: allowBackup
            self.args.max_sdk_version = max_sdk_version
            res = self.analyzer.isAutoBackupAllowed()
            self.assertEqual(res, expected, f"{allowBackup=} and {max_sdk_version=} should produce {expected} but produced {res}")
    
    def test_showApkInfo(self):
        # the tuple elements represents :
        # getSdkVersion[0] (uses_sdk_min_sdk_version), getSdkVersion[1](uses_sdk_max_sdk_version),
        # args_min_sdk_version, args_max_sdk_version, expectedResult
        testCases = [
            ((15, 30), 15, 30, 0),
            ((15, 30), 20, 30, 1),
            ((15, 30), 20, 30, 1),
            ((15, 30), 20, 31, 3),
            ((15, 30), 15, 31, 2),
            ((15, 30), 1, 30, 1),
            ((15, 30), 1, 31, 3),
            ((15, 30), 15, 0, 2),
            ((15, 30), 16, 0, 3),
            ((15, 30), 1, 0, 3),
            ((0, 0), 15, 30, 0),
            ((1, 0), 15, 30, 1),
            ((0, 4), 15, 30, 2),
            ((13, 4), 15, 30, 3),
            ((15, 0), 15, 30, 0),
            ((0, 30), 15, 30, 0),
            ((1, 30), 15, 30, 1),
        ]
        Info = namedtuple("Info", "package versionCode versionName")
        self.parser.getApkInfo = lambda: Info("pack", "12", "1.2")
        self.parser.componentStats = lambda x: 0
        self.parser.exportedComponentStats = lambda x: 0
        U = namedtuple("Uses", "name required")
        self.parser.usesLibrary = lambda: [U("test", None)]
        self.parser.usesNativeLibrary = lambda: [U("test1", None)]
        self.parser.usesFeatures = lambda: [U("test2", None)]
        for testCase in testCases:
            getSdkVersion = testCase[0]
            min_sdk_version = testCase[1]
            max_sdk_version = testCase[2]
            expected = testCase[3]
            self.parser.getSdkVersion = lambda: getSdkVersion
            self.args.min_sdk_version = min_sdk_version
            self.args.max_sdk_version = max_sdk_version
            res = self.analyzer.showApkInfo()
            self.assertEqual(res, expected, f"{getSdkVersion=} and {min_sdk_version=} and {max_sdk_version=} should produce {expected} but produced {res}")
    

    def test_analyzeExportedComponent(self):
        # the tuple elements represents :
        # getExportedComponentPermission[0] (name), getExportedComponentPermission[1] (type),
        # getExportedComponentPermission[2] (permission), getExportedComponentPermission[3] (readPermission),
        # getExportedComponentPermission[4] (writePermission) getExportedComponentPermission[5] (grantUriPermissions)
        ExportedComponents = namedtuple("ExportedComponents", "componentName componentType permission readPermission writePermission grantUriPermissions")

        testCases = [
            ([ExportedComponents("deadbeef", "activity", "deadbeef_perm", None, None, None)], 2),
            ([ExportedComponents("deadbeef", "service", "deadbeef_perm", None, None, None)], 2),
            ([ExportedComponents("deadbeef", "receiver", "deadbeef_perm", None, None, None)], 2),
            ([ExportedComponents("deadbeef", "activity", None, None, None, None)], 1),
            ([ExportedComponents("deadbeef", "service", None, None, None, None)], 1),
            ([ExportedComponents("deadbeef", "receiver", None, None, None, None)], 1),
            ([ExportedComponents("deadbeef", "provider", None, None, None, None)], 1),
            ([ExportedComponents("deadbeef", "provider", "deadbeef_perm", None, None, None)], 2),
            ([ExportedComponents("deadbeef", "provider", None, "deadbeef_perm", None, None)], 2),
            ([ExportedComponents("deadbeef", "provider", None, None, "deadbeef_perm", None)], 2),
        ]

        self.parser.getUniversalLinks = lambda: []
        for testCase in testCases:
            getExportedComponentPermission = testCase[0]
            expected = testCase[1]
            self.parser.getExportedComponentPermission = lambda t: [e for e in getExportedComponentPermission if e.componentType == t]
            res = self.analyzer.analyzeExportedComponent()
            self.assertEqual(res, expected, f"{getExportedComponentPermission=} should produce {expected} but produced {res}")

    def test_isBackupAgentImplemented(self):
        # the tuple elements represents :
        # backupAgent, expectedResult
        testCases = [
            (".MyBackupAgent", True),
            (None, False),
            ("", False),
        ]

        for testCase in testCases:
            backupAgent = testCase[0]
            expected = testCase[1]
            self.parser.backupAgent = lambda: backupAgent
            res = self.analyzer.isBackupAgentImplemented()
            self.assertEqual(res, expected, f"{backupAgent=} should produce {expected} but produced {res}")

    def test_getBackupRulesFile(self):
        # the tuple elements represents :
        # fullBackupContent, dataExtractionRules, args_min_sdk, args_max_sdk, expectedResult
        testCases = [
            ("test.xml", "test.xml", 15, 30, 1),
            ("test.xml", "test.xml", 15, 31, 3),
            ("test.xml", "test.xml", 31, 32, 2),
            ("test.xml", "test.xml", 30, 31, 3),
            (None, "test.xml", 15, 30, 0),
            (None, "test.xml", 31, 32, 2),
            (None, "test.xml", 17, 31, 2),
            ("test.xml", None, 15, 30, 1),
            ("test.xml", None, 31, 32, 0),
            ("test.xml", None, 17, 31, 1),
            (None, None, 15, 30, 0),
            (None, None, 15, 31, 0),
            (None, None, 31, 32, 0),
        ]

        Rule = namedtuple("Rule", "type domain path requireFlags")
        ExtractionRules = namedtuple("ExtractionRules", "cloudBackupRules disableIfNoEncryptionCapabilities deviceTransferRules")
        r = Rule("a", "b", "c", "d")
        self.parser.getFullBackupContentRules = lambda: [r]
        self.parser.getDataExtractionRulesContent = lambda: ExtractionRules([r], True, [r])

        for testCase in testCases:
            fullBackupContent = testCase[0]
            dataExtractionRules = testCase[1]
            min_sdk_version = testCase[2]
            max_sdk_version = testCase[3]
            expected = testCase[4]
            self.parser.fullBackupContent = lambda: fullBackupContent
            self.parser.dataExtractionRules = lambda : dataExtractionRules
            self.args.min_sdk_version = min_sdk_version
            self.args.max_sdk_version = max_sdk_version
            res = self.analyzer.getBackupRulesFile()
            self.assertEqual(res, expected, f"{fullBackupContent=} and {dataExtractionRules=} and {min_sdk_version} and {max_sdk_version} should produce {expected} but produced {res}")

    def test_getNetworkConfigFile(self):
        # the tuple elements represents :
        # networkSecurityConfig, expectedResult
        testCases = [
            ("network_security_config", True),
            (None, False)
        ]
        self.analyzer.analyzeNSCTrustAnchors = lambda: None
        for testCase in testCases:
            networkSecurityConfig = testCase[0]
            expected = testCase[1]
            self.parser.networkSecurityConfig = lambda: networkSecurityConfig
            res = self.analyzer.getNetworkConfigFile()
            self.assertEqual(res, expected, f"{networkSecurityConfig=} should produce {expected} but produced {res}")

    def test_isDebuggable(self):
        # the tuple elements represents :
        # debuggable, expectedResult
        testCases = [
            (True, True),
            (False, False),
            (None,False)
        ]
        self.parser.hasFile = lambda x: True
        for testCase in testCases:
            debuggable = testCase[0]
            expected = testCase[1]
            self.parser.debuggable = lambda: debuggable
            res = self.analyzer.isDebuggable()
            self.assertEqual(res, expected, f"{debuggable=} should produce {expected} but produced {res}")


    def test_isCleartextTrafficAllowed(self):
        # the tuple elements represents :
        # usesCleartextTraffic, min_sdk_version, max_sdk_version, networkSecurityConfig, expectedResult
        testCases = [
            (True, 20, 21, None, True),
            (True, 20, 21, "sd", True),
            (False, 20, 21, None, False),
            (False, 20, 21, "sd", False),
            (None, 20, 21, None, True),
            (None, 20, 21, "sd", True),

            (True, 20, 24, None, True),
            (True, 20, 24, "sd", (True, None)),
            (False, 20, 24, None, False),
            (False, 20, 24, "sd", (False, None)),
            (None, 20, 24, None, True),
            (None, 20, 24, "sd", (True, None)),

            (True, 23, 25, None, True),
            (True, 23, 25, "sd", (True, None)),
            (False, 23, 25, None, False),
            (False, 23, 25, "sd", (False, None)),
            (None, 23, 25, None, True),
            (None, 23, 25, "sd", (True, None)),

            (True, 24, 25, None, True),
            (True, 24, 25, "sd", None),
            (False, 24, 25, None, False),
            (False, 24, 25, "sd", None),
            (None, 24, 25, None, True),
            (None, 24, 25, "sd", None),
            (True, 26, 27, None, True),
            (True, 26, 27, "sd", None),
            (False, 26, 27, None, False),
            (False, 26, 27, "sd", None),
            (None, 26, 27, None, True),
            (None, 26, 27, "sd", None),

            (True, 27, 28, None, True),
            (True, 27, 28, "sd", None),
            (False, 27, 28, None, False),
            (False, 27, 28, "sd", None),
            (None, 27, 28, None, (True, False)),
            (None, 27, 28, "sd", None),

            (True, 28, 30, None, True),
            (True, 28, 30, "sd", None),
            (False, 28, 30, None, False),
            (False, 28, 30, "sd", None),
            (None, 28, 30, None, False),
            (None, 28, 30, "sd", None),

            (True, 10, 30, None, True),
            (True, 10, 30, "sd", (True, None)),
            (False, 10, 30, None, False),
            (False, 10, 30, "sd", (False, None)),
            (None, 10, 30, None, (True, False)),
            (None, 10, 30, "sd", (True, None)),
        ]
        self.analyzer.analyzeNSCClearTextTraffic = lambda: None
        for testCase in testCases:
            usesCleartextTraffic = testCase[0]
            min_sdk_version = testCase[1]
            max_sdk_version = testCase[2]
            networkSecurityConfig = testCase[3]
            expected = testCase[4]
            self.parser.networkSecurityConfig = lambda: networkSecurityConfig
            self.parser.usesCleartextTraffic = lambda: usesCleartextTraffic
            self.args.min_sdk_version = min_sdk_version
            self.args.max_sdk_version = max_sdk_version
            res = self.analyzer.isCleartextTrafficAllowed()
            self.assertEqual(expected, res, f"{usesCleartextTraffic=} and {min_sdk_version=} and {max_sdk_version=} and {networkSecurityConfig=} should produce {expected} but produced {res}")

    def test_isDeepLinkUsed(self):
        # the tuple elements represents :
        # getUniversalLinks, expectedResult
        UniversalLink = namedtuple("UniversalLink", "name tag autoVerify uris hosts")

        testCases = [
            ([UniversalLink("","","",["host"],["host"])], True),
            ([], False),
        ]

        for testCase in testCases:
            getUniversalLinks = testCase[0]
            expected = testCase[1]
            self.parser.getUniversalLinks = lambda: getUniversalLinks
            res = self.analyzer.isDeepLinkUsed()
            self.assertEqual(res, expected, f"{getUniversalLinks=} should produce {expected} but produced {res}")

    def test_isAppLinkUsed(self):
        # the tuple elements represents :
        # getUniversalLinks, expectedResult
        UniversalLink = namedtuple("UniversalLink", "name tag autoVerify uris hosts")

        testCases = [
            ([UniversalLink("","","",["host"],["host"])], 0),
            ([], 0),
            ([UniversalLink("", "", True, ["host"], ["host"])], 1),
            ([
                 UniversalLink("", "", True, ["host"], ["host"]),
                 UniversalLink("", "", None, ["host"], ["host"])
             ], 1),
            ([
                 UniversalLink("", "", True, ["host"], ["host"]),
                 UniversalLink("", "", False, ["ddzad"], ["ddzad"])
             ], 1),
            ([
                 UniversalLink("", "", True, ["host"], ["host"]),
                 UniversalLink("", "", True, ["ddzad"], ["ddzad"])
             ], 2),
            ([
                 UniversalLink("", "", True, ["host"], ["host"]),
                 UniversalLink("", "", True, ["host"], ["host"])
             ], 1),
        ]

        for testCase in testCases:
            getUniversalLinks = testCase[0]
            expected = testCase[1]
            self.parser.getUniversalLinks = lambda: getUniversalLinks
            res = self.analyzer.isAppLinkUsed()
            self.assertEqual(res, expected,f"{getUniversalLinks=} should produce {expected} but produced {res}")


    def test_analyzeNSCClearTextTraffic(self):
        # the tuple elements represents :
        # min_sdk_version, ma_sdk_version, BConfig.cleartextTrafficPermitted, expectedResult
        testCases = [
            (25, 27, True, True),
            (25, 30, True, True),
            (29, 30, True, True),
            (28, 29, True, True),
            (27, 28, True, True),
            (25, 27, False, False),
            (25, 30, False, False),
            (29, 30, False, False),
            (28, 29, False, False),
            (27, 28, False, False),
            (25, 27, None, True),
            (25, 30, None, (True, False)),
            (29, 30, None, False),
            (28, 29, None, False),
            (27, 28, None, (True, False)),
        ]

        config = namedtuple("BConfig", "cleartextTrafficPermitted trustanchors")
        def d(dcs=None, inheritedCT=False, withCT=True):
            return ["a", "b"]
        self.parser.getAllDomains = d
        for testCase in testCases:
            min_sdk_version = testCase[0]
            max_sdk_version = testCase[1]
            cleartextTrafficPermitted = testCase[2]
            expected = testCase[3]
            self.parser.getBaseConfig = lambda: config(cleartextTrafficPermitted, [])
            self.args.min_sdk_version = min_sdk_version
            self.args.max_sdk_version = max_sdk_version
            res = self.analyzer.analyzeNSCClearTextTraffic(self.parser)
            self.assertEqual(expected, res,
                             f"{min_sdk_version=} and {max_sdk_version=} and {cleartextTrafficPermitted=} should produce {expected} but produced {res}")


    def test_analyzeNSCTrustAnchors(self):
        # the tuple elements represents :
        # min_sdk_version, max_sdk_version, BConfig.trustanchors, expectedResult
        cert = namedtuple("Cert", "src overridePins")
        c = cert("a", False)
        testCases = [
            (13, 23, [], 2),
            (13, 20, [], 2),
            (13, 23, [c, c, c], 3),
            (13, 20, [c, c, c, c, c, c], 6),
            (24, 25, [], 1),
            (24, 30, [], 1),
            (28, 39, [c, c, c], 3),
            (28, 30, [c, c, c, c, c, c], 6),
            (23, 24, [], (2, 1)),
            (23, 24, [], (2, 1)),
            (23, 24, [c, c, c], 3),
            (23, 24, [c, c, c, c, c, c], 6),
        ]

        config = namedtuple("BConfig", "cleartextTrafficPermitted trustanchors")
        def d(dcs=None, inheritedTA=False):
            domainConf = namedtuple("DomainConf", "domain, trustanchors")
            return [domainConf("aa", [])]
        self.parser.getDomainsWithTA = d
        for testCase in testCases:
            min_sdk_version = testCase[0]
            max_sdk_version = testCase[1]
            trustanchors = testCase[2]
            expected = testCase[3]
            self.parser.getBaseConfig = lambda: config(True, trustanchors)
            self.args.min_sdk_version = min_sdk_version
            self.args.max_sdk_version = max_sdk_version
            res = self.analyzer.analyzeNSCTrustAnchors(self.parser)
            self.assertEqual(expected, res,
                             f"{min_sdk_version=} and {max_sdk_version=} and {trustanchors=} should produce {expected} but produced {res}")


if __name__ == '__main__':
    unittest.main(buffer=True)