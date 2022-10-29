#!/usr/bin/env python3
import argparse
from src.parser import Parser
from src.apkParser import APKParser
from src.analyzer import Analyzer
from src.constants import ANDROID_MAX_SDK
import logging

if __name__ == "__main__":
    argparser = argparse.ArgumentParser(description='Utility to analyse Android Manifest files.')
    argparser.add_argument('--log-level', '-v', type=int, choices=[0, 1, 2], help='Sets the log level', default=0)
    argparser.add_argument("path", help="The path to the manifest file.")
    argparser.add_argument("--min-sdk-version", '-min', type=int, choices=range(1,ANDROID_MAX_SDK+1), help='Indicate the minimum version supported by your application', metavar=f"[1,{ANDROID_MAX_SDK}]", required=True)
    argparser.add_argument("--max-sdk-version", '-max', type=int, choices=range(1,ANDROID_MAX_SDK+1), help='Indicate the maximum version supported by your application', metavar=f"[1,{ANDROID_MAX_SDK}]", required=True)
    args = argparser.parse_args()

    assert args.min_sdk_version <= args.max_sdk_version, "min SDK version cannot be higher than max SDK version"

    # silence https://github.com/appknox/pyaxmlparser/blob/d111a4fc6330a0c293ffc2f114af360eb78ad2ef/pyaxmlparser/stringblock.py#L208
    log = logging.getLogger("pyaxmlparser.stringblock")
    log.setLevel(logging.CRITICAL)
    # silence https://github.com/appknox/pyaxmlparser/blob/d111a4fc6330a0c293ffc2f114af360eb78ad2ef/pyaxmlparser/arscparser.py#L150
    log = logging.getLogger("pyaxmlparser.arscparser")
    log.setLevel(logging.CRITICAL)

    # try as APK
    parser = APKParser(args.path)
    if parser.apk is None:
        # not an APK file
        parser = Parser(args.path)
    analyzer = Analyzer(parser, args)
    analyzer.runAllTests()

    # showcase parser unused features
    # print(parser.getFullBackupContentRules())
    # print(parser.getDataExtractionRulesContent())
