# How to contribute to AMAnDe

## Did you find a bug?
If you do not want to/can't solve the bug, please open an issue after checking there isn't a similar one already opened.

## Did you write a patch that fixes a bug?
Open a new GitHub pull request with the patch and ensure the description clearly describes the problem and solution.
On the other hand, if the bug you found is due to a misinterpretation of the documentation from our side, please indicate the new link you relied on.

## Did you fix whitespace, format code, or make a purely cosmetic patch?
If the change is really relevant and helps to improve the readability/intelligibility of the output, please open a new pull request. 
Otherwise, minor changes such as title colors/bold etc. will not be accepted.

## Do you intend to add a new feature or change an existing one?
Please open a pull request with a precise description. Do not forget to add any relevant link (documentation etc.)


Be careful, any modification must be validated via new unit tests or meet the unit tests already implemented.
Do not forget to add unit tests to your pull request when implementing a new feature.

Here is how you can launch the existing unit tests and do some profiling :
```bash
python3 -m unittest -b unitTests/tests.py
python3 -m cProfile -s 'cumulative' main.py -max 23 -min 18 examples/AndroidManifest.xml
```

