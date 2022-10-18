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
./main.py examples/AndroidManifest.xml
```

## todo
- terminer la fonction analyseBuiltinsPerms
- implementer les tests sur les custom perms
- def isAppLinkUsed 
- def isDeepLinkUsed 
- def receiverAnalysis 
- def providerAnalysis
- def servicesAnalysis
- def activitiesAnalysis