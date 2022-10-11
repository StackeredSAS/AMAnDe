#!/usr/bin/env python3

import logging
from termcolor import colored


class Logger:
	def __init__(self):
		logging.basicConfig(format='%(levelname)s:%(message)s', level=logging.INFO)
		logging.addLevelName(logging.ERROR, "ERROR")
		logging.addLevelName(logging.WARNING, "[!]")
		logging.addLevelName(logging.INFO, "[+]")

	def test(self, message):
		logging.error(message)