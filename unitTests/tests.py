#!/usr/bin/env python3
import unittest
from src.analyzer import Analyzer
from src.parser import Parser
import logging
logging.disable(logging.CRITICAL)

class FakeParser(Parser):
    # a fake parser class that allows init with no args
    def __init__(self):
        pass

class TestAnalyzer(unittest.TestCase):
    # We do not test the parser it is assumed the parsing is done correctly.
    # This allows much simpler unit tests writing. No need to generated custom manifests.
    parser = FakeParser()
    # fake args
    from collections import namedtuple
    args = namedtuple("a", "log_level max_sdk_version min_sdk_version")
    args.log_level = "INFO"
    analyzer = Analyzer(parser, args)

    def test_isADBBackupAllowed(self):
        # the tuple elements represents :
        # allowBackup, expectedResult
        testCases = [
            (True, True),
            (False, False),
            (None, True)
        ]

        for testCase in testCases:
            allowBackup = testCase[0]
            expected = testCase[1]
            self.parser.allowBackup = lambda: allowBackup
            res = self.analyzer.isADBBackupAllowed()
            self.assertEqual(res, expected, f"{allowBackup=} should produce {expected} but produced {res}")

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
        # fullBackupContent, dataExtractionRules, expectedResult
        testCases = [
            ("test.xml", "test.xml", 3),
            (None, "test.xml", 2),
            ("test.xml", None, 1),
            (None, None, 0),
        ]

        for testCase in testCases:
            fullBackupContent = testCase[0]
            dataExtractionRules = testCase[1]
            expected = testCase[2]
            self.parser.fullBackupContent = lambda: fullBackupContent
            self.parser.dataExtractionRules = lambda : dataExtractionRules
            res = self.analyzer.getBackupRulesFile()
            self.assertEqual(res, expected, f"{fullBackupContent=} and {dataExtractionRules=} should produce {expected} but produced {res}")

    def test_getNetworkConfigFile(self):
        # the tuple elements represents :
        # networkSecurityConfig, expectedResult
        testCases = [
            ("network_security_config", True),
            (None, False)
        ]

        for testCase in testCases:
            networkSecurityConfig = testCase[0]
            expected = testCase[1]
            self.parser.networkSecurityConfig = lambda: networkSecurityConfig
            res = self.analyzer.getNetworkConfigFile()
            self.assertEqual(res, expected, f"{networkSecurityConfig=} should produce {expected} but produced {res}")

if __name__ == '__main__':
    unittest.main(buffer=True)