import os
import sys

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
sys.path.insert(0, os.path.join(BASE_DIR, 'scripts'))

from calibrate_corpus_10k import calibrate

def generate_corpus_table():
    calibrate()

if __name__ == "__main__":
    generate_corpus_table()