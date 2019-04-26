#!/bin/bash
unset LD_LIBRARY_PATH
args=("$@")
./mx-sync-policies.py ${args[0]}