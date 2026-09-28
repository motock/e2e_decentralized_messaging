# sitecustomize.py
# Ensure the current working directory is on sys.path for tests
import os, sys
sys.path.insert(0, os.getcwd())
