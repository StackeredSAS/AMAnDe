#!/usr/bin/env python3
import argparse
from src.parser import Parser
from src.apkParser import APKParser
from src.analyzer import Analyzer
from src.constants import ANDROID_MAX_SDK
import logging
from src.utils import CustomFormatter


if __name__ == "__main__":
    argparser = argparse.ArgumentParser(description='Utility to analyse Android Manifest files.')
    argparser.add_argument('--log-level', '-v', type=int, choices=[0, 1, 2], help='Sets the log level', default=0)
    argparser.add_argument("path", help="The path to the manifest file.")
    argparser.add_argument("--min-sdk-version", '-min', type=int, choices=range(1, ANDROID_MAX_SDK+1),
                           help='Indicate the minimum version supported by your application',
                           metavar=f"[1,{ANDROID_MAX_SDK}]", required=True)
    argparser.add_argument("--max-sdk-version", '-max', type=int, choices=range(1, ANDROID_MAX_SDK+1),
                           help='Indicate the maximum version supported by your application',
                           metavar=f"[1,{ANDROID_MAX_SDK}]", required=True)
    args = argparser.parse_args()

    assert args.min_sdk_version <= args.max_sdk_version, "min SDK version cannot be higher than max SDK version"

    # silence https://github.com/appknox/pyaxmlparser/blob/d111a4fc6330a0c293ffc2f114af360eb78ad2ef/pyaxmlparser
    # /stringblock.py#L208
    logging.getLogger("pyaxmlparser.stringblock").setLevel(logging.CRITICAL)
    # silence https://github.com/appknox/pyaxmlparser/blob/d111a4fc6330a0c293ffc2f114af360eb78ad2ef/pyaxmlparser
    # /arscparser.py#L150
    logging.getLogger("pyaxmlparser.arscparser").setLevel(logging.CRITICAL)

    logger = logging.getLogger("MainLogger")
    logger.setLevel(logging.INFO)
    if args.log_level == 1:
        logger.setLevel(logging.WARNING)
    elif args.log_level == 2:
        logger.setLevel(logging.ERROR)

    # Create stdout handler for logging to the console
    stdout_handler = logging.StreamHandler()
    stdout_handler.setFormatter(CustomFormatter())
    # Add handlers to the logger
    logger.addHandler(stdout_handler)

    # try as APK
    parser = APKParser(args.path)
    if parser.apk is None:
        # not an APK file
        parser = Parser(args.path)
    analyzer = Analyzer(parser, args)
    analyzer.runAllTests()
