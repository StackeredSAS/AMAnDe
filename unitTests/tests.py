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
    analyzer = Analyzer(parser, args)

    def test_isADBBackupAllowed(self):
        # the tuple elements represents :
        # allowBackup, debuggable, target_sdk_version, expectedResult
        testCases = [
            (True, True, 25, True),
            (True, True, 30, True),
            (True, True, 31, True),
            (True, True, 32, True),
            (True, False, 25, True),
            (True, False, 30, True),
            (True, False, 31, False),
            (True, False, 32, False),

            (False, True, 25, False),
            (False, True, 30, False),
            (False, True, 31, False),
            (False, True, 32, False),
            (False, False, 25, False),
            (False, False, 30, False),
            (False, False, 31, False),
            (False, False, 32, False),

            (None, True, 25, True),
            (None, True, 30, True),
            (None, True, 31, True),
            (None, True, 32, True),
            (None, False, 25, True),
            (None, False, 30, True),
            (None, False, 31, False),
            (None, False, 32, False),

            (None, None, 25, True),
            (None, None, 30, True),
            (None, None, 31, False),
            (None, None, 32, False),
            (None, None, 25, True),
            (None, None, 30, True),
            (None, None, 31, False),
            (None, None, 32, False),

            (True, None, 25, True),
            (True, None, 30, True),
            (True, None, 31, False),
            (True, None, 32, False),
            (True, None, 25, True),
            (True, None, 30, True),
            (True, None, 31, False),
            (True, None, 32, False),

            (False, None, 25, False),
            (False, None, 30, False),
            (False, None, 31, False),
            (False, None, 32, False),
            (False, None, 25, False),
            (False, None, 30, False),
            (False, None, 31, False),
            (False, None, 32, False),

        ]


        for testCase in testCases:
            allowBackup = testCase[0]
            debuggable = testCase[1]
            target_sdk_version = testCase[2]
            expected = testCase[3]
            self.parser.allowBackup = lambda: allowBackup
            self.parser.debuggable = lambda: debuggable
            self.args.target_sdk_version = target_sdk_version

            if allowBackup is None:
                allowBackup = True

            res = self.analyzer.isADBBackupAllowed()
            self.assertEqual(expected, res, f"{allowBackup=} and {target_sdk_version=} and {debuggable=} should "
                                            f"produce {expected} but produced {res}")

    def test_isAutoBackupAllowed(self):
        # the tuple elements represents :
        # allowBackup, fullBackupOnly, backupAgent, min_sdk_version, max_sdk_version, target_sdk_version expectedResult
        testCases = [
            # CASE 1 : No Auto-Backup because < 23
            (True, True, None, 12, 20, 20, False),
            (True, False, None, 12, 20, 20, False),
            (True, None, None, 12, 20, 20, False),
            (True, True, "test", 12, 20, 20, False),
            (True, False, "test", 12, 20, 20, False),
            (True, None, "test", 12, 20, 20, False),

            (False, True, None, 12, 20, 20, False),
            (False, False, None, 12, 20, 20, False),
            (False, None, None, 12, 20, 20, False),
            (False, True, "test", 12, 20, 20, False),
            (False, False, "test", 12, 20, 20, False),
            (False, None, "test", 12, 20, 20, False),

            # CASE 2 : SAME as case 1 but maybe with an ambiguous trigger
            (True, True, None, 12, 22, 22, False),
            (True, False, None, 12, 22, 22, False),
            (True, None, None, 12, 22, 22, False),
            (True, True, "test", 12, 22, 22, False),
            (True, False, "test", 12, 22, 22, False),
            (True, None, "test", 12, 22, 22, False),

            (False, True, None, 12, 22, 22, False),
            (False, False, None, 12, 22, 22, False),
            (False, None, None, 12, 22, 22, False),
            (False, True, "test", 12, 22, 22, False),
            (False, False, "test", 12, 22, 22, False),
            (False, None, "test", 12, 22, 22, False),

            # CASE 3 : With an ambiguous trigger
            (True, True, None, 12, 23, 23, (True, False)),
            (True, False, None, 12, 23, 23, (True, False)),
            (True, None, None, 12, 23, 23, (True, False)),
            (True, True, "test", 12, 23, 23, (True, False)),
            # Return False because if fullBackupOnly is False, Auto-Backup is performed only when backupAgent is None
            (True, False, "test", 12, 23, 23, False),
            (True, None, "test", 12, 23, 23, False),

            (False, True, None, 12, 23, 23, False),
            (False, False, None, 12, 23, 23, False),
            (False, None, None, 12, 23, 23, False),
            (False, True, "test", 12, 23, 23, False),
            (False, False, "test", 12, 23, 23, False),
            (False, None, "test", 12, 23, 23, False),

            # CASE 4 : With an ambiguous trigger, before encryption can be available and without version that do not
            # support Auto-Backup
            (True, True, None, 23, 26, 26, (True, False)),
            (True, False, None, 23, 26, 26, (True, False)),
            (True, None, None, 23, 26, 26, (True, False)),
            (True, True, "test", 23, 26, 26, (True, False)),
            # Return False because if fullBackupOnly is False, Auto-Backup is performed only when backupAgent is None
            (True, False, "test", 23, 26, 26, False),
            (True, None, "test", 23, 26, 26, False),

            (False, True, None, 23, 26, 26, False),
            (False, False, None, 23, 26, 26, False),
            (False, None, None, 23, 26, 26, False),
            (False, True, "test", 23, 26, 26, False),
            (False, False, "test", 23, 26, 26, False),
            (False, None, "test", 23, 26, 26, False),


            # CASE 5 : With all
            (True, True, None, 20, 28, 27, (True,(False,True))),
            (True, False, None, 20, 28, 27, (True,(False,True))),
            (True, None, None, 20, 28, 27, (True,(False,True))),
            (True, True, "test", 20, 28, 27, (True,(False,True))),
            (True, False, "test", 20, 28, 27, False),
            (True, None, "test", 20, 28, 27, False),

            (False, True, None, 20, 28, 27, False),
            (False, False, None, 20, 28, 27, False),
            (False, None, None, 20, 28, 27, False),
            (False, True, "test", 20, 28, 27, False),
            (False, False, "test", 20, 28, 27, False),
            (False, None, "test", 20, 28, 27, False),


            # CASE 6 : With max > target an ambiguous trigger
            (True, True, None, 23, 27, 26, (True, False)),
            (True, False, None, 23, 27, 26, (True, False)),
            (True, None, None, 23, 27, 26, (True, False)),
            (True, True, "test", 23, 27, 26, (True, False)),
            # Return False because if fullBackupOnly is False, Auto-Backup is performed only when backupAgent is None
            (True, False, "test", 23, 27, 26, False),
            (True, None, "test", 23, 27, 26, False),

            (False, True, None, 23, 27, 26, False),
            (False, False, None, 23, 27, 26, False),
            (False, None, None, 23, 27, 26, False),
            (False, True, "test", 23, 27, 26, False),
            (False, False, "test", 23, 27, 26, False),
            (False, None, "test", 23, 27, 26, False),


            # CASE 7 : With max > target an ambiguous trigger which take encrypted and unencpryted
            (True, True, None, 23, 28, 26, (True, (False, True))),
            (True, False, None, 23, 28, 26, (True, (False, True))),
            (True, None, None, 23, 28, 26, (True, (False, True))),
            (True, True, "test", 23, 28, 26, (True, (False, True))),
            # Return False because if fullBackupOnly is False, Auto-Backup is performed only when backupAgent is None
            (True, False, "test", 23, 28, 26, False),
            (True, None, "test", 23, 28, 26, False),

            (False, True, None, 23, 28, 26, False),
            (False, False, None, 23, 28, 26, False),
            (False, None, None, 23, 28, 26, False),
            (False, True, "test", 23, 28, 26, False),
            (False, False, "test", 23, 28, 26, False),
            (False, None, "test", 23, 28, 26, False),


            # CASE 8 : With version that do not support encryption and without version that do not
            # support Auto-Backup and with an ambiguous trigger
            (True, True, None, 25, 28, 28, (True,(False,True))),
            (True, False, None, 23, 28, 28, (True, (False, True))),
            (True, None, None, 23, 28, 28, (True, (False, True))),
            (True, True, "test", 23, 28, 28, (True, (False, True))),
            # Return False because if fullBackupOnly is False, Auto-Backup is performed only when backupAgent is None
            (True, False, "test", 23, 28, 28, False),
            (True, None, "test", 23, 28, 28, False),

            (False, True, None, 23, 28, 28, False),
            (False, False, None, 23, 28, 28, False),
            (False, None, None, 23, 28, 28, False),
            (False, True, "test", 23, 28, 28, False),
            (False, False, "test", 23, 28, 28, False),
            (False, None, "test", 23, 28, 28, False),

            # CASE 9 : With version that do not support encryption and without version that do not
            # support Auto-Backup and with an ambiguous trigger
            (True, True, None, 28, 30, 30, (True, True)),
            (True, False, None, 28, 30, 30, (True, True)),
            (True, None, None, 28, 30, 30, (True, True)),
            (True, True, "test", 28, 30, 30, (True, True)),
            # Return False because if fullBackupOnly is False, Auto-Backup is performed only when backupAgent is None
            (True, False, "test", 28, 30, 30, False),
            (True, None, "test", 28, 30, 30, False),

            (False, True, None, 28, 30, 30, False),
            (False, False, None, 28, 30, 30, False),
            (False, None, None, 28, 30, 30, False),
            (False, True, "test", 28, 30, 30, False),
            (False, False, "test", 28, 30, 30, False),
            (False, None, "test", 28, 30, 30, False),

        ]

        for testCase in testCases:
            allowBackup = testCase[0]
            fullBackupOnly = testCase[1]
            backupAgent = testCase[2]
            min_sdk_version = testCase[3]
            max_sdk_version = testCase[4]
            target_sdk_version = testCase[5]
            expected = testCase[6]
            self.parser.allowBackup = lambda: allowBackup
            self.parser.fullBackupOnly = lambda: fullBackupOnly
            self.parser.backupAgent = lambda: backupAgent
            self.args.min_sdk_version = min_sdk_version
            self.args.max_sdk_version = max_sdk_version
            self.args.target_sdk_version = target_sdk_version
            res = self.analyzer.isAutoBackupAllowed()
            self.assertEqual(expected, res,
                             f"{allowBackup=} and {fullBackupOnly=} and {backupAgent=} and {min_sdk_version=} "
                             f"and {max_sdk_version=} and {target_sdk_version=} should produce {expected} but produced {res}")


    def test_showApkInfo(self):
        # the tuple elements represents :
        # getSdkVersion (uses_sdk_min_sdk_version, uses_sdk_target_sdk_version, uses_sdk_max_sdk_version),
        # args_min_sdk_version, args_target_sdk_version, args_max_sdk_version, expectedResult
        testCases = [
            ((15, 20, 30), 15, 20, 30, 0),
            ((15, 20, 30), 20, 20, 30, 1),
            ((15, 20, 30), 20, 20, 31, 3),
            ((15, 20, 30), 15, 20, 31, 2),
            ((15, 20, 30), 1, 20, 30, 1),
            ((15, 20, 30), 1, 20, 31, 3),
            ((15, 20, 30), 15, 20, 0, 2),
            ((15, 20, 30), 16, 20, 0, 3),
            ((15, 20, 30), 1, 20, 0, 3),
            ((0, 0, 0), 15, 8, 30, 0),
            ((1, 0, 0), 15, 0, 30, 1),
            ((0, 0, 4), 15, 0, 30, 2),
            ((13, 0, 4), 15, 0, 30, 3),
            ((15, 0, 0), 15, 0, 30, 0),
            ((0, 0, 30), 15, 0, 30, 0),
            ((1, 0, 30), 15, 0, 30, 1),
            ((15, 20, 30), 15, 16, 30, 4),
            ((15, 20, 30), 11, 16, 30, 5),
            ((15, 20, 30), 11, 16, 31, 7),
            ((15, 20, 30), 11, 16, 31, 7),
            ((1, 1, 30), 15, 3, 30, 5),
            ((0, 1, 0), 15, 16, 30, 4),
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
            target_sdk_version = testCase[2]
            max_sdk_version = testCase[3]
            expected = testCase[4]
            self.parser.getSdkVersion = lambda: getSdkVersion
            self.args.min_sdk_version = min_sdk_version
            self.args.max_sdk_version = max_sdk_version
            self.args.target_sdk_version = target_sdk_version
            res = self.analyzer.showApkInfo()
            self.assertEqual(expected, res, f"{getSdkVersion=} and {min_sdk_version=} and {target_sdk_version=} "
                                            f"and {max_sdk_version=} should produce {expected} but produced {res}")

    def test_analyzeExportedComponent(self):
        # the tuple elements represents :
        # getExportedComponentPermission[0] (name), getExportedComponentPermission[1] (type),
        # getExportedComponentPermission[2] (permission), getExportedComponentPermission[3] (readPermission),
        # getExportedComponentPermission[4] (writePermission) getExportedComponentPermission[5] (grantUriPermissions)
        ExportedComponents = namedtuple("ExportedComponents", "componentName componentType permission readPermission "
                                                              "writePermission grantUriPermissions")

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
            self.parser.getExportedComponentPermission = lambda t: [e for e in getExportedComponentPermission
                                                                    if e.componentType == t]
            res = self.analyzer.analyzeExportedComponent()
            self.assertEqual(expected, res, f"{getExportedComponentPermission=} should produce {expected} "
                                            f"but produced {res}")

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
            self.assertEqual(expected, res, f"{backupAgent=} should produce {expected} but produced {res}")

    def test_getBackupRulesFile(self):
        # the tuple elements represents :
        # fullBackupContent, dataExtractionRules, args_min_sdk, args_target_sdk, expectedResult
        testCases = [
            ("test.xml", "test.xml", 15, 30, 1),
            ("test.xml", "test.xml", 15, 31, 2),
            ("test.xml", "test.xml", 31, 32, 2),
            ("test.xml", "test.xml", 30, 31, 2),
            (None, "test.xml", 15, 30, 0),
            (None, "test.xml", 31, 32, 2),
            (None, "test.xml", 17, 31, 2),
            ("test.xml", None, 15, 30, 1),
            ("test.xml", None, 31, 32, 0),
            ("test.xml", None, 17, 31, 0),
            (None, None, 15, 30, 0),
            (None, None, 15, 31, 0),
            (None, None, 31, 32, 0),
        ]

        Rule = namedtuple("Rule", "type domain path requireFlags")
        ExtractionRules = namedtuple("ExtractionRules", "cloudBackupRules disableIfNoEncryptionCapabilities "
                                                        "deviceTransferRules")
        r = Rule("a", "b", "c", "d")
        self.parser.getFullBackupContentRules = lambda: [r]
        self.parser.getDataExtractionRulesContent = lambda: ExtractionRules([r], True, [r])

        for testCase in testCases:
            fullBackupContent = testCase[0]
            dataExtractionRules = testCase[1]
            min_sdk_version = testCase[2]
            target_sdk_version = testCase[3]
            expected = testCase[4]
            self.parser.fullBackupContent = lambda: fullBackupContent
            self.parser.dataExtractionRules = lambda: dataExtractionRules
            self.args.min_sdk_version = min_sdk_version
            self.args.target_sdk_version = target_sdk_version
            res = self.analyzer.getBackupRulesFile()
            self.assertEqual(expected, res, f"{fullBackupContent=} and {dataExtractionRules=} and {min_sdk_version=} "
                                            f"and {target_sdk_version=} should produce {expected} but produced {res}")

    def test_getNetworkConfigFile(self):
        # the tuple elements represents :
        # networkSecurityConfig, expectedResult
        testCases = [
            ("network_security_config", True),
            (None, False)
        ]
        self.analyzer.analyzeNSCTrustAnchors = lambda: None
        self.analyzer.analyzeNSCPinning = lambda: None
        for testCase in testCases:
            networkSecurityConfig = testCase[0]
            expected = testCase[1]
            self.parser.networkSecurityConfig = lambda: networkSecurityConfig
            res = self.analyzer.getNetworkConfigFile()
            self.assertEqual(expected, res, f"{networkSecurityConfig=} should produce {expected} but produced {res}")

    def test_isDebuggable(self):
        # the tuple elements represents :
        # debuggable, expectedResult
        testCases = [
            (True, True),
            (False, False),
            (None, False)
        ]
        self.parser.hasFile = lambda x: True
        for testCase in testCases:
            debuggable = testCase[0]
            expected = testCase[1]
            self.parser.debuggable = lambda: debuggable
            res = self.analyzer.isDebuggable()
            self.assertEqual(expected, res, f"{debuggable=} should produce {expected} but produced {res}")

    def test_isCleartextTrafficAllowed(self):
        # the tuple elements represents :
        # usesCleartextTraffic, min_sdk_version, max_sdk_version, target_sdk_version, networkSecurityConfig, expectedResult
        testCases = [
            (True, 20, 21, 21, None, True),
            (True, 20, 21, 21, "sd", True),
            (False, 20, 21, 21, None, False),
            (False, 20, 21, 21, "sd", False),
            (None, 20, 21, 21, None, True),
            (None, 20, 21, 21, "sd", True),

            (True, 20, 24, 24, None, True),
            (True, 20, 24, 24, "sd", (True, None)),
            (False, 20, 24, 24, None, False),
            (False, 20, 24, 24, "sd", (False, None)),
            (None, 20, 24, 24, None, True),
            (None, 20, 24, 24, "sd", (True, None)),

            (True, 20, 28, 27, None, True),
            (True, 20, 28, 27, "sd", (True, None)),
            (False, 20, 28, 27, None, False),
            (False, 20, 28, 27, "sd", (False, None)),
            (None, 20, 28, 27, None, True),
            (None, 20, 28, 27, "sd", (True, None)),

            (True, 20, 32, 30, None, True),
            (True, 20, 32, 30, "sd", (True, None)),
            (False, 20, 32, 30, None, False),
            (False, 20, 32, 30, "sd", (False, None)),
            (None, 20, 32, 30, None, False),
            (None, 20, 32, 30, "sd", (False, None)),

            (True, 23, 25, 24, None, True),
            (True, 23, 25, 24, "sd", (True, None)),
            (False, 23, 25, 24, None, False),
            (False, 23, 25, 24, "sd", (False, None)),
            (None, 23, 25, 24, None, True),
            (None, 23, 25, 24, "sd", (True, None)),

            (True, 24, 25, 25, None, True),
            (True, 24, 25, 25, "sd", None),
            (False, 24, 25, 25, None, False),
            (False, 24, 25, 25, "sd", None),
            (None, 24, 25, 25, None, True),
            (None, 24, 25, 25, "sd", None),

            (True, 26, 27, 27, None, True),
            (True, 26, 27, 27, "sd", None),
            (False, 26, 27, 27, None, False),
            (False, 26, 27, 27, "sd", None),
            (None, 26, 27, 27, None, True),
            (None, 26, 27, 27, "sd", None),

            (True, 27, 28, 28, None, True),
            (True, 27, 28, 28, "sd", None),
            (False, 27, 28, 28, None, False),
            (False, 27, 28, 28, "sd", None),
            (None, 27, 28, 28, None, False),
            (None, 27, 28, 28, "sd", None),

            (True, 28, 33, 30, None, True),
            (True, 28, 33, 30, "sd", None),
            (False, 28, 33, 30, None, False),
            (False, 28, 33, 30, "sd", None),
            (None, 28, 33, 30, None, False),
            (None, 28, 33, 30, "sd", None),

        ]
        self.analyzer.analyzeNSCClearTextTraffic = lambda: None
        for testCase in testCases:
            usesCleartextTraffic = testCase[0]
            min_sdk_version = testCase[1]
            max_sdk_version = testCase[2]
            target_sdk_version = testCase[3]
            networkSecurityConfig = testCase[4]
            expected = testCase[5]
            self.parser.networkSecurityConfig = lambda: networkSecurityConfig
            self.parser.usesCleartextTraffic = lambda: usesCleartextTraffic
            self.args.min_sdk_version = min_sdk_version
            self.args.max_sdk_version = max_sdk_version
            self.args.target_sdk_version = target_sdk_version
            res = self.analyzer.isCleartextTrafficAllowed()
            self.assertEqual(expected, res, f"{usesCleartextTraffic=} and {min_sdk_version=} and {max_sdk_version=} and {target_sdk_version=} and"
                                            f" {networkSecurityConfig=} should produce {expected} but produced {res}")

    def test_isDeepLinkUsed(self):
        # the tuple elements represents :
        # getUniversalLinks, expectedResult
        UniversalLink = namedtuple("UniversalLink", "name tag autoVerify uris hosts")

        testCases = [
            ([UniversalLink("", "", "", ["host"], ["host"])], True),
            ([], False),
        ]

        for testCase in testCases:
            getUniversalLinks = testCase[0]
            expected = testCase[1]
            self.parser.getUniversalLinks = lambda: getUniversalLinks
            res = self.analyzer.isDeepLinkUsed()
            self.assertEqual(expected, res, f"{getUniversalLinks=} should produce {expected} but produced {res}")

    def test_isAppLinkUsed(self):
        # the tuple elements represents :
        # getUniversalLinks, expectedResult
        UniversalLink = namedtuple("UniversalLink", "name tag autoVerify uris hosts")

        testCases = [
            ([UniversalLink("", "", "", ["host"], ["host"])], 0),
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
            self.assertEqual(expected, res, f"{getUniversalLinks=} should produce {expected} but produced {res}")

    def test_analyzeNSCClearTextTraffic(self):
        # todo: incorrect comprehension of the documentation
        # the tuple elements represents :
        # target_sdk_version, BConfig.cleartextTrafficPermitted, expectedResult
        testCases = [
            (23, True, True),
            (24, True, True),
            (25, True, True),
            (27, True, True),
            (28, True, True),
            (30, True, True),
            (32, True, True),

            (23, False, False),
            (24, False, False),
            (25, False, False),
            (27, False, False),
            (28, False, False),
            (30, False, False),
            (32, False, False),

            (23, None, True),
            (24, None, True),
            (25, None, True),
            (27, None, True),
            (28, None, False),
            (30, None, False),
            (32, None, False),
        ]

        config = namedtuple("BConfig", "cleartextTrafficPermitted trustanchors")

        def d(dcs=None, inheritedCT=False, withCT=True):
            return ["a", "b"]

        self.parser.getAllDomains = d
        for testCase in testCases:
            target_sdk_version = testCase[0]
            cleartextTrafficPermitted = testCase[1]
            expected = testCase[2]
            self.parser.getBaseConfig = lambda: config(cleartextTrafficPermitted, [])
            self.args.target_sdk_version = target_sdk_version
            res = self.analyzer.analyzeNSCClearTextTraffic(self.parser)
            self.assertEqual(expected, res, f"{target_sdk_version=} and "
                                            f"{cleartextTrafficPermitted=} should produce {expected} "
                                            f"but produced {res}")

    def test_analyzeNSCTrustAnchors(self):
        # todo: incorrect comprehension of the documentation
        # the tuple elements represents :
        # target_sdk_version, BConfig.trustanchors, expectedResult
        cert = namedtuple("Cert", "src overridePins")
        c = cert("a", False)
        testCases = [
            (20, [], 2),
            (23, [c, c, c], 3),
            (20, [c, c, c, c, c, c], 6),
            (25, [], 1),
            (30, [], 1),
            (33, [c, c, c], 3),
            (30, [c, c, c, c, c, c], 6),
            (28, [], 1),
            (27, [c, c, c], 3),
            (24, [c, c, c, c, c, c], 6),            
        ]

        config = namedtuple("BConfig", "cleartextTrafficPermitted trustanchors")

        def d(dcs=None, inheritedTA=False):
            domainConf = namedtuple("DomainConf", "domain, trustanchors")
            return [domainConf("aa", [])]

        self.parser.getDomainsWithTA = d
        for testCase in testCases:
            target_sdk_version = testCase[0]
            trustanchors = testCase[1]
            expected = testCase[2]
            self.parser.getBaseConfig = lambda: config(True, trustanchors)
            self.args.target_sdk_version = target_sdk_version
            res = self.analyzer.analyzeNSCTrustAnchors(self.parser)
            self.assertEqual(expected, res, f"{target_sdk_version=} and {trustanchors=} "
                                            f"should produce {expected} but produced {res}")

    def test_analyzeNSCPinning(self):
        # the tuple elements represents :
        # domainConf, expectedResult
        domainConf = namedtuple("DomainConf", "domain pinset overridePins")
        # just test different cases but only to assert there is no crash
        # there is nothing else to test really
        testCases = [
            ([domainConf("a", "2012-01-01", [])], None),
            ([domainConf("a", "2100-01-01", [])], None),
            ([domainConf("a", "2012-01-01", ["ss"])], None),
            ([domainConf("a", "2100-01-01", ["sss"])], None),
            ([domainConf("a", "2012-01-01", ["ss", "sdsqd"])], None),
            ([domainConf("a", "2100-01-01", ["sss", "qsdfqq"])], None),
        ]

        def d(inheritedTA=False):
            return parsed

        self.parser.getPinningInfo = d
        self.parser.getBaseConfig = lambda: None
        for testCase in testCases:
            parsed = testCase[0]
            expected = testCase[1]
            res = self.analyzer.analyzeNSCPinning(self.parser)
            self.assertEqual(expected, res, f"{parsed=} should produce {expected} but produced {res}")

if __name__ == '__main__':
    unittest.main(buffer=True)
