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
        # the tuple elements represents :
        # allowBackup, minSdkVersion, expectedResult
        testCases = [
            (True, 0, True),
            (True, 25, True),
            (True, 1, True),
            (False, 24, False),
            (False, 2, False),
            (False, 0, False),
            (None, 5, None),
            (None, 23, True),
            (None, 0, None),
        ]

        for testCase in testCases:
            allowBackup = testCase[0]
            minSdkVersion = testCase[1]
            expected = testCase[2]
            self.parser.allowBackup = lambda: allowBackup
            self.parser.minSdkVersion = lambda: minSdkVersion
            res = self.analyzer.isBackupAllowed()
            self.assertEqual(res, expected, f"{allowBackup=} and {minSdkVersion=} should produce {expected} but produced {res}")


if __name__ == '__main__':
    unittest.main(buffer=True)