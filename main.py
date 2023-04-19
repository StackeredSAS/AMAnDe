#!/usr/bin/env python3
import argparse
import sys
from src.parser import Parser
from src.apkParser import APKParser
from src.analyzer import Analyzer
from src.constants import ANDROID_MAX_SDK
import logging
from src.utils import CustomFormatter
from src.external import downloadAPK
import tempfile
import xml.etree.ElementTree


if __name__ == "__main__":
    argparser = argparse.ArgumentParser(description='Utility to analyse Android Manifest files.')
    argparser.add_argument('--log-level', '-v', type=int, choices=[0, 1, 2], help='Sets the log level', default=0)
    argparser.add_argument("path", help="The path to the manifest file.")
    argparser.add_argument("--min-sdk-version", '-min', type=int, choices=range(1, ANDROID_MAX_SDK+1),
                           help='Indicate the minimum version supported by your application',
                           metavar=f"[1,{ANDROID_MAX_SDK}]", required=True)
    argparser.add_argument("--target-sdk-version", '-target', type=int, choices=range(1, ANDROID_MAX_SDK + 1),
                           help='Indicate the version targeted by your application '
                                '(default : same as --min-sdk-version)',
                           metavar=f"[1,{ANDROID_MAX_SDK}]")
    argparser.add_argument("--max-sdk-version", '-max', type=int, choices=range(1, ANDROID_MAX_SDK+1),
                           help='Indicate the maximum version supported by your application (default : %(default)s)',
                           metavar=f"[1,{ANDROID_MAX_SDK}]", default=ANDROID_MAX_SDK)
    argparser.add_argument('--adb', action="store_true", help='Indicates to use ADB. The path argument is treated as '
                                                              'the app\'s package name')
    argparser.add_argument('--json', metavar="file", help='Export the results in JSON format to a file.')
    args = argparser.parse_args()
    # just follow the same rule as Android for the default value
    args.target_sdk_version = args.target_sdk_version or args.min_sdk_version
    assert args.min_sdk_version <= args.max_sdk_version, "min SDK version cannot be higher than max SDK version"
    assert args.target_sdk_version <= args.max_sdk_version, "target SDK version cannot be higher than max SDK version"
    assert args.min_sdk_version <= args.target_sdk_version, "min SDK version cannot be higher than target SDK version"

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

    with tempfile.TemporaryDirectory() as tmpPath:
        packageName = None
        if args.adb:
            packageName = args.path
            args.path = downloadAPK(args.path, tmpPath)

            if args.path is None:
                logger.error("Invalid package name !")
                sys.exit(1)

        try:
            # try as APK
            parser = APKParser(args.path)
            if parser.apk is None:
                # not an APK file
                parser = Parser(args.path)

        except FileNotFoundError:
            logger.error("Invalid file name !")
            sys.exit(1)
        except xml.etree.ElementTree.ParseError:
            logger.error("Invalid file !")
            sys.exit(1)

        analyzer = Analyzer(parser, args)
        analyzer.packageName = packageName
        analyzer.runAllTests()