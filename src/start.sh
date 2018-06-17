#!/bin/bash

python3 setup.py -r 7 3 2

python3 client.py 1 &
python3 client.py 2 &

python3 main.py 1 &
python3 main.py 2 &
python3 main.py 3 &
python3 main.py 4 &
python3 main.py 5 &
python3 main.py 6 &
python3 main.py 7 &

