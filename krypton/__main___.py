import os, sys, pathlib

os.chdir(pathlib.Path(__file__).parent.parent.as_posix())
print(os.system(sys.executable + " -m unittest discover -s tests -p \"*test*.py\" --verbose"))
