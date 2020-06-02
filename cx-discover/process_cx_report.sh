#!/bin/bash
unset LD_LIBRARY_PATH
args=("$@")
python process_cx_report.py ${args[0]} ${args[1]} ${args[2]}