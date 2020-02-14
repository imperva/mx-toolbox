#!/bin/bash
unset LD_LIBRARY_PATH
args=("$@")
python export_report_to_s3.py ${args[0]} ${args[1]} ${args[2]}