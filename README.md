# XXX
XXX is a new tool to analyze the following Android XML files taking into account Android versions and there corresponding default values and configurations :
- AndroidManifest
- fullBackupContent
- dataExtractionRules
- network_security_config

If you want all those files to be parsed, you must submit an APK file. Otherwise, give the script a simple Manifest file
but the results will not be as relevant. 

Checks and information provided when an APK file is given are the following :
- APK generic information including
  - package name
  - version code and name if specified in the Manifest
  - min and max Android SDK version
  - Number of components (activities, services, providers, receivers) including those exported
  - Shared libraries required
  - Vendor provided share native library required
  - Hardware or software features required
  - output of apksigner (if installed) to check the signature
- Analyze required permissions
  - builtins
    - Searching dangerous one
  - customs
    - Analyzing declaration and protectionLevel specified by the developer
- Analyzing backup functionality
  - ADB
  - Auto-Backup
  - Kotlin or Java agent
  - fullBackupContent file content analysis (if exists)
  - dataExtractionRules file content analysis (if exists)
- Compilation mode
- network_security_config.xml analysis if file exists
  - trust anchors configuration
  - certificate pinning
- clear text traffic property
- Listing exported components
- Summarizing information about all exported components which specified Intent Filters (all available uris, data, category etc.)
  - Deeplink (uris for all activities)
  - Applink (uris, check if Digital Asset Link JSON file are publicly available)
- Analyzing permissions set on exported components
- Listing un-exported providers which specify grantUriPermissions set to True
- Looking for Firebase URL


Checks and information provided when only a Manifest file is given are the following :
- Same as above without fullBackupContent, dataExtractionRules and network_security_config content files analysis


## Installation
```bash
python3 -m pip install -r requirements.txt
```

## Usage
Using the script requires to specify the following mandatory options :
- the version range (min/max Android SDK versions) in which the application is intended to work (this information can be found in the build.gradle or by asking the developer)
- the path to the AndroidManifest.xml or APK file

XXX is developed with its own logger which can take value 0,1 and 2 to respectively display INFO, WARNING or CRITICAL information.

```bash
./main.py -h
./main.py -max 23 -min 18 examples/AndroidManifest.xml
./main.py -max 23 -min 18 examples/AndroidManifest.xml -v 1
./main.py -max 23 -min 18 examples/example.apk -v 2
```

## todo
- tests avec outils tiers si préinstallés
  - Trouver d'autres outils utiles (ABE)
- support de ADB pour completer certains tests (ex: backups) et faire du dynamique
- faire un vrai readme
- Donner quelques manifest d'example plus propres
- A faire à la toute fin:
  - revoir les documentations manquantes
  - revoir le PEP8
  - revoir les fautes d'orthographe
  - tenter d'installer l'outil sur un docker ubuntu clean pour valider la procédure d'install
  - passer le répo en public ou en faire un nouveau (si on veut pas l'historique des commits)
