# ManifestAnalyzer
Parsing and analyzing AndroidManifest.xml


## Installation

```
python3 -m pip install -r requirements.txt
python3 -m unittest -b unitTests/tests.py
python3 -m cProfile -s 'cumulative' main.py -max 23 -min 18 examples/AndroidManifest.xml
```

## Compiling example APK without Android Studio
```
aapt2 compile --dir <path_to_res_directory> -o <name_of_output_zip>
aapt2 link <name_of_output_zip> -o <name_of_output_apk> -I <path_to_android.jar or apk> --manifest <path_to_the_Manifest> -v
```

example (requires apktool) : 

```
git clone https://github.com/codepath/intro_android_demo.git
aapt2 compile --dir intro_android_demo/app/src/main/res/ -o resources.zip
aapt2 link resources.zip -o test.apk --manifest intro_android_demo/app/src/main/AndroidManifest.xml -I /Users/florianpicca/Library/apktool/framework/1.apk -v
unzip -l test.apk
```

## Usage

```
./main.py -h
./main.py -max 23 -min 18 examples/AndroidManifest.xml
./main.py -max 23 -min 18 examples/AndroidManifest.xml -v 1
./main.py -max 23 -min 18 examples/example.apk
```

## todo
- APK info
  - counter de activity-alias (a voir si on le regroupe ou pas)
- def providerAnalysis
	- FileProvider
- si apk check for kernel.bin (flutter app)
- tests avec outils tiers si préinstallés
  - apksigner pour les signatures
- vérifier les infos du network sec conf (pinning, trust anchors)
- vérifier les infos des backup rules file (data extract rules et full backup content)
- support de ADB pour completer certains tests (ex: backups) et faire du dynamique
- vérifier qu'un deeplink est forcément sans permission (i.e. analyzeExportedComponent)
- fix getBackupRulesFile to take into account Android versions (< 11 and > 12)