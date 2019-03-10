# Python module for NFC communication

## Install

Run the following commands in order:
1. `virtualenv python-2`
2. `source python-2/bin/activate`
3. `python setup.py develop`
4. `pip install -r requirements-dev.txt`

## Run

To launch the simultaneous multi-reader implementation, run:
```
python examples/tagtool.py --loop
```