#!/usr/bin/env python3
import argparse
from src.parser import Parser
from src.analyzer import Analyzer
from src.constants import (
    ANDROID_MIN_SDK,
    ANDROID_MAX_SDK
    )

if __name__ == "__main__":
    argparser = argparse.ArgumentParser(description='Utility to analyse Android Manifest files.')
    argparser.add_argument('--log-level', '-v', choices=['INFO', 'WARNING', 'ERROR'], help='Sets the log level', default="INFO")
    argparser.add_argument("path", help="The path to the manifest file.")
    argparser.add_argument("--min-sdk-version", type=int, choices=range(ANDROID_MIN_SDK,ANDROID_MAX_SDK+1), help='Indicate the minimum version supported by your application', metavar='['+str(ANDROID_MIN_SDK)+']', required=True)
    argparser.add_argument("--max-sdk-version", type=int, choices=range(ANDROID_MIN_SDK,ANDROID_MAX_SDK+1), help='Indicate the maximum version supported by your application', metavar='['+str(ANDROID_MAX_SDK)+']', required=True)
    args = argparser.parse_args()

    parser = Parser(args.path)
    analyzer = Analyzer(parser)
    analyzer.setLogLevel(args.log_level)
    analyzer.runAllTests()
    #analyzer.getPerms()
