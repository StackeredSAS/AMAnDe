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
- tests avec outils tiers si préinstallés
  - surcouche apksigner ?
  - faire une fonction séparée ?
- Analyser les infos du network sec conf:
  - pinning
  - trust anchors
- support de ADB pour completer certains tests (ex: backups) et faire du dynamique
- fullBackupOnly
- revoir toutes les fonctions avec intervalles de version
  - isAutoBackupAllowed (a l'air ok, a refire aven handle version ?)
  - getBackupRulesFile