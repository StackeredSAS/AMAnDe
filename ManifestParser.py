#!/usr/bin/env python3

import xml.etree.ElementTree as ET
from tabulate import tabulate
import termcolor
from Logger import *

#TODO : add color to print result in green, orange or red (from criticity).
#TODO : add install script (gradle, codeql etc.)
#TODO : add codeql project compilation
#TODO : add parsing for codeql result
#TODO : add codeql execution specifiying directory with all rules
#TODO : add command line args to specify Manifest file path
#TODO :  add network security_config analysis

FILE_NAME = "AndroidManifest.xml"

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

# Define format for logs
#fmt = '%(levelname)s | %(message)s'

# Create stdout handler for logging to the console (logs all five levels)
stdout_handler = logging.StreamHandler()
stdout_handler.setLevel(logging.INFO)
stdout_handler.setFormatter(CustomFormatter())

# Add both handlers to the logger
logger.addHandler(stdout_handler)


class ManifestParser:

	def __init__(self):
		self.FILE_NAME = FILE_NAME
		self.namespaces = {'android': 'http://schemas.android.com/apk/res/android',
						   'tools': 'http://schemas.android.com/tools'}
		self.root = ET.parse(FILE_NAME).getroot()



	def apkInfo():
		#package, versionname,versioncode
		print("TBD")


	def androidPermissions(self):
		header = ["name"]
		table = []

		print("APK will require the following permissions at runtime")
		for android_perm in self.root.findall('uses-permission'):
			#print(list(android_perm.attrib.values())[0])
		
			builtin_permissions = [android_perm.get("{"+self.namespaces["android"]+"}name")]
			table.append(builtin_permissions)
		
		print(tabulate(table, header, tablefmt="github"))


	def appPermissions(self):
		headers = ["name", "protectionLevel"]
		table = []

		print("APK create its own following permissions")
		for app_perm in self.root.findall('permission'):
			if(not app_perm.attrib):
				print("APK only uses builtin Android permissions")
			else:
				app_permissions = [app_perm.get("{"+self.namespaces["android"]+"}name")]
				app_permissions.append(app_perm.get("{"+self.namespaces["android"]+"}protectionLevel"))
				table.append(app_permissions)

		print(tabulate(table, headers, tablefmt="github"))
		# TEST LOG
		logger.info("This is an info")
		logger.warning("This is a warning to pay attention")
		logger.error("This is an error")



	def isBackupAllowed(self,allowBackup,fullBackupContent):
		if (allowBackup == None or allowBackup == "true"):
			print("APK can be backuped (from Android 6, backup is authorized even if allowBackup property is not defined in the Manifest)")
			if(fullBackupContent):
				xml_file_name = fullBackupContent.split("/")[1]
				print(f'Custom XML rules has been defined to control what gets backed up in "{xml_file_name}" file')
			else:
				print("fullBackupContent property not found -> please make a backup for further controls")
		else:
			print("allowBackup property not found -> APK can not be backuped")


	def isClearTextTrafficAllowed(self, usesCleartextTraffic):
		if(usesCleartextTraffic):
			print("usesCleartextTraffic value is 'true'. This app may intends to use cleartext network traffic, such as HTTP.")
		else:
			print("usesCleartextTraffic not found -> check minimum API level supported and the official doc to get more info")



	def isDebugAllowed(self, debuggable):
		if (debuggable == "true"):
			print("APK is compiled in debug mode")
		else:
			print("debuggable property not found -> false by default")



	def isNetworkSecurityConfigDefined(self, networkSecurityConfig): 
		if (networkSecurityConfig):
			xml_file_name = networkSecurityConfig.split("/")[1]
			print(f'APK network security config is defined in "{xml_file_name}" file')
		else:
			print("APK seems not to use network_security_config.xml file")


	def applicationAttributes(self):
		for application in self.root.findall("application"):
			allowBackup = application.get("{"+self.namespaces["android"]+"}allowBackup")
			fullBackupContent = application.get("{"+self.namespaces["android"]+"}fullBackupContent")
			usesCleartextTraffic = application.get("{"+self.namespaces["android"]+"}usesCleartextTraffic")
			debuggable = application.get("{"+self.namespaces["android"]+"}debuggable")
			networkSecurityConfig = application.get("{"+self.namespaces["android"]+"}networkSecurityConfig")

			#TODO : fullbackupContent

		self.isBackupAllowed(allowBackup,fullBackupContent)
		self.isClearTextTrafficAllowed(usesCleartextTraffic)
		self.isDebugAllowed(debuggable)
		self.isNetworkSecurityConfigDefined(networkSecurityConfig)



	def activitiesAnalysis(self):
		activity_counter = 0
		intent_filter_counter = 0
		intent_filter_action_counter = 0
		activities = {}
		intent_filters = {}
		intent_filter_action = []
		intent_filter_category = []

'''
def isAppLinkUsed():
	print("test4")

def isDeepLinkUsed():
	print("test5")

def receiverAnalysis():
	print("test7")

def providerAnalysis():
	print("test8")

def servicesAnalysis():
	print("test9")
'''






