#!/usr/bin/env python3
import argparse
from src.parser import Parser
from src.analyzer import Analyzer

if __name__ == "__main__":
    argparser = argparse.ArgumentParser(description='Utility to analyse Android Manifest files.')
    argparser.add_argument('--log-level', '-v', choices=['INFO', 'WARNING', 'ERROR'], help='Sets the log level', default="INFO")
    argparser.add_argument("path", help="The path to the manifest file.")
    args = argparser.parse_args()

    parser = Parser(args.path)
    analyzer = Analyzer(parser)
    analyzer.setLogLevel(args.log_level)
    analyzer.runAllTests()
    #analyzer.getPerms()
