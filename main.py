#!/usr/bin/env python3
import argparse
from src.parser import Parser
from src.analyzer import Analyzer
from src.constants import ANDROID_MAX_SDK

if __name__ == "__main__":
    argparser = argparse.ArgumentParser(description='Utility to analyse Android Manifest files.')
    argparser.add_argument('--log-level', '-v', choices=['INFO', 'WARNING', 'CRITICAL'], help='Sets the log level', default="INFO")
    argparser.add_argument("path", help="The path to the manifest file.")
    argparser.add_argument("--min-sdk-version", '-min', type=int, choices=range(1,ANDROID_MAX_SDK+1), help='Indicate the minimum version supported by your application', metavar=f"[1,{ANDROID_MAX_SDK}]", required=True)
    argparser.add_argument("--max-sdk-version", '-max', type=int, choices=range(1,ANDROID_MAX_SDK+1), help='Indicate the maximum version supported by your application', metavar=f"[1,{ANDROID_MAX_SDK}]", required=True)
    args = argparser.parse_args()

    assert args.min_sdk_version <= args.max_sdk_version, "min SDK version cannot be higher than max SDK version"

    parser = Parser(args.path)
    analyzer = Analyzer(parser, args)
    analyzer.runAllTests()





    # showcase parser unused features
    '''
    print("-" * 20)
    print(f"{parser.debuggable()=}")
    print(f"{parser.usesCleartextTraffic()=}")
    for e in parser.customPermissions():
        print(f"{e.name} | {e.permissionGroup} | {e.protectionLevel}")
    print(parser.exportedServices())
    '''
    print(f'{parser.exportedComponents("dddd")=}')
    print(f'{parser.componentStats("provider")=}')
    print(f'{parser.exportedComponentStats("activity")=}')
    #print(parser.getApkInfo())