# AMAnDe
## What's AMAnDe
AMAnDe stands for Android Manifest ANomaly Detector.
It's a new tool whose objective is to extract and gather information from an Android Manifest.
When we deal with huge Manifests, it is often difficult to get all relevant datas (like deeplink URIs, exported provider, etc.)
With AMAnDe all of those are informations are deeply analyzed presented to you in a simple manner.

AMAnDe can also directly take an APK file as input. In this case, the following files (if exist) will also be analyzed :
- fullBackupContent
- dataExtractionRules
- network_security_config

All results take into consideration Android versions and their corresponding default values and configurations. 


## Installation
```bash
python3 -m pip install -r requirements.txt
```

## Usage
Using the script requires to specify the following mandatory options :
- the version range (min/max Android SDK versions) in which the application is intended to work (this information can be found in the build.gradle or by asking the developer)
- the path to the AndroidManifest.xml or APK file

AMAnDe is developed with its own logger which can take value 0,1 and 2 to respectively display INFO, WARNING or CRITICAL information.

```bash
./main.py -h
./main.py -max 23 -min 18 examples/AndroidManifest.xml
./main.py -max 23 -min 18 examples/AndroidManifest.xml -v 1
./main.py -max 23 -min 18 examples/example.apk -v 2
```
If you want interesting XML files (backup rules and network_security_config) to be parsed, please submit an APK file. Otherwise, give the script a simple Manifest file
but the results will not be as relevant. 

## Checks
### Basic information
- package name
- version code and name if specified in the Manifest
- min and max Android SDK version
- Number of components (activities, services, providers, receivers) including those exported
- Shared libraries required
- Vendor provided share native library required
- Hardware or software features required
- Compilation mode

With an APK:
- All the above
- output of apksigner (if installed) to check the signature

### Permissions
- builtins
  - Searching dangerous ones (i.e. READ_CONTACTS etc.)
- customs
  - Analyzing declaration and protectionLevel specified by the developer

### Backup functionality
- ADB
- Auto-Backup
- Kotlin or Java backupAgent

With an APK:
- All the above
- fullBackupContent file content analysis (if it exists)
- dataExtractionRules file content analysis (if it exists)

### Network Security Config
With an APK and if the file exists:
- Trust anchors configuration
- Certificate pinning 
- Clear text traffic configuration

### Components
- Listing exported components
- Summarizing information about all exported components specifying Intent Filters (URIs, data, category etc.)
  - Deeplink (URIs)
  - Applink (URIs and checks if Digital Asset Link JSON files are publicly available)
- Analyzing permissions set on exported components
- Listing un-exported providers specifying grantUriPermissions to True

### Firebase
- Looking for Firebase URL


## Contributing
We encourage any contribution aiming at improving this tool. If you want to contribute
please check our guidelines in [CONTRIBUTING](CONTRIBUTING.md).


## todo
- support de ADB pour completer certains tests (ex: backups) et faire du dynamique
- faire un vrai readme -> en cours
- Donner quelques manifest d'example plus propres
- A faire à la toute fin:
  - revoir le PEP8
  - revoir les fautes d'orthographe
  - tenter d'installer l'outil sur un docker ubuntu clean pour valider la procédure d'install
  - passer le répo en public ou en faire un nouveau (si on veut pas l'historique des commits)

```bash
adb shell 'bu backup -apk -all -nosystem' > backup.ab
```

Android backup extractor :
```bash
java -jar abe.jar unpack backup.ab backup.tar
tar -xf backup.tar
```