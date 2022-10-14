#!/usr/bin/env python3
import unittest
from src.analyzer import Analyzer
from src.parser import Parser

class FakeParser(Parser):
    # a fake parser class that allows init with no args
    def __init__(self):
        pass

class TestAnalyzer(unittest.TestCase):
    # We do not test the parser it is assumed the parsing is done correctly.
    # This allows much simpler unit tests writing. No need to generated custom manifests.
    parser = FakeParser()
    analyzer = Analyzer(parser)

    def test_isBackupAllowed(self):
        # allowBackup : true and no SDK
        self.parser.allowBackup = lambda: True
        self.parser.minSdkVersion = lambda: 0
        res = self.analyzer.isBackupAllowed()
        # backup should be allowed
        self.assertEqual(res, True, "allowBackup : True and no SDK")

        # allowBackup : true and SDK > 23
        self.parser.allowBackup = lambda: True
        self.parser.minSdkVersion = lambda: 25
        res = self.analyzer.isBackupAllowed()
        # backup should be allowed
        self.assertEqual(res, True, "allowBackup : True and SDK > 23")

        # allowBackup : false and SDK > 23
        self.parser.allowBackup = lambda: False
        self.parser.minSdkVersion = lambda: 24
        res = self.analyzer.isBackupAllowed()
        # backup should not be allowed
        self.assertEqual(res, False, "allowBackup : False and SDK > 23")

        # allowBackup : false and SDK < 23
        self.parser.allowBackup = lambda: False
        self.parser.minSdkVersion = lambda: 2
        res = self.analyzer.isBackupAllowed()
        # backup should not be allowed
        self.assertEqual(res, False, "allowBackup : False and SDK < 23")

        # allowBackup : None and SDK < 23
        self.parser.allowBackup = lambda: None
        self.parser.minSdkVersion = lambda: 5
        res = self.analyzer.isBackupAllowed()
        # we shouldn't know
        self.assertEqual(res, None, "allowBackup : None and SDK < 23")

        # allowBackup : None and SDK >= 23
        self.parser.allowBackup = lambda: None
        self.parser.minSdkVersion = lambda: 23
        res = self.analyzer.isBackupAllowed()
        # backup should be allowed
        self.assertEqual(res, True, "allowBackup : None and SDK >= 23")

if __name__ == '__main__':
    unittest.main(buffer=True)