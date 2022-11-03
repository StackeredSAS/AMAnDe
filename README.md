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
- Ce serait intéressant de pouvoir vérifier si les WARNING META INF sont présent dans la sortie d'apksigner et le cas échéant de les enlever et de rajouter un message d'info ou d'erreur (si juste le schéma V1 est utilisé) 
