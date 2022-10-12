#!/usr/bin/env python3

import sys
from ManifestParser import *

try:
	obj = ManifestParser()
	obj.androidPermissions()
	obj.appPermissions()
	obj.applicationAttributes()
	obj.activitiesAnalysis()

except FileNotFoundError:
	print("Input file can not be found, exiting...")
	sys.exit(0)