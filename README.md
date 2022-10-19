# ManifestAnalyzer
Parsing and analyzing AndroidManifest.xml


## Installation

```
python3 -m pip install -r requirements.txt
python3 -m unittest -b unitTests/tests.py
```

## Usage

```
./main.py -h
./main.py -max 23 -min 18 examples/AndroidManifest.xml
./main.py -max 23 -min 18 examples/AndroidManifest.xml -v WARNING
./main.py -max 23 -min 18 examples/example.apk
```

## todo
- tester avec des APK compilées avec aapt et aapt2
- corrgier les crash de getResourceTypeName (APK only)
- terminer la fonction analyseBuiltinsPerms
- implementer les tests sur les custom perms
- def isAppLinkUsed 
- def isDeepLinkUsed 
- def receiverAnalysis 
- def providerAnalysis
- def servicesAnalysis
- def activitiesAnalysis
- checker si sdk mismatch entre args et manifest (dans apkinfo)