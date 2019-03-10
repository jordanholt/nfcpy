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
python app/kitchen-readers.py
```

## Troubleshooting

When readers are first connected on Linux, they may be locked by the Linux NFC subsystem kernel driver. To release them, run:
```
sudo modprobe -r pn533_usb
```

Other errors and potential fixes can be found by running:
```
python -m nfc
```