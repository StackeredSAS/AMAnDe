# ManifestAnalyzer
Parsing and analyzing AndroidManifest.xml


## Installation

```
python3 -m pip install -r requirements.txt
python3 -m unittest -b unitTests/tests.py
```

## Compiling example APK without Android Studio
```
//https://developer.android.com/studio/command-line/aapt2
//Using aapt2 implies to compile all resources of the project and then link it to create an apk
//Intermediate resource file have the .flat extension and output is a zip containing all these files

aapt2 compile --dir <path_to_res_directory> -o <name_of_output_zip>
unzip -d resources <name_of_output_zip>
aapt2 link resources/* -o <name_of_output_apk> <path_to_android.jar_resource_file> --manifest <path_to_the_Manifest> -v
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
- def isAppLinkUsed 
- def isDeepLinkUsed 
- def receiverAnalysis 
- def providerAnalysis
- def servicesAnalysis
- def activitiesAnalysis
- checker si sdk mismatch entre args et manifest (dans apkinfo)