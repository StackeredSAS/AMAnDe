#!/usr/bin/env python3
import argparse
from src.parser import Parser
from src.analyzer import Analyzer

if __name__ == "__main__":
    argparser = argparse.ArgumentParser(description='Utility to analyse Android Manifest files.')
    argparser.add_argument('--log-level', '-v', choices=['INFO', 'WARNING', 'ERROR'], help='Sets the log level', default="INFO")
    argparser.add_argument("path", help="The path to the manifest file.")
    argparser.add_argument("--min-sdk-version", type=int, choices=range(ANDROID_MIN_SDK,ANDROID_MAX_SDK+1), help='Indicate the minimum version supported by your application', metavar=f"[{ANDROID_MIN_SDK}, {ANDROID_MAX_SDK}]", required=True)
    args = argparser.parse_args()

    parser = Parser(args.path)
    analyzer = Analyzer(parser, args)
    analyzer.runAllTests()
