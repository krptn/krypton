from ast import arg
import subprocess
import sys

proc = subprocess.Popen(executable=sys.executable,
    args="",
    stdin=sys.stdin,tdout=sys.stdout)

proc.communicate(b"import pysec \r")
print("Proccess exited with code: ",proc.wait())
