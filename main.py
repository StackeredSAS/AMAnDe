#!/usr/bin/env python3

from src.parser import Parser
from src.analyzer import Analyzer

if __name__ == "__main__":
    # todo argparse
    parser = Parser("examples/AndroidManifest.xml")
    analyzer = Analyzer(parser)
    analyzer.runAllTests()
    #analyzer.getPerms()
