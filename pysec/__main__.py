import subprocess
import sys

proc = subprocess.Popen(executable=sys.executable,
    args="",
    stdin=sys.stdin,stdout=sys.stdout)

print("HI, from PySec")
print("Proccess exited with code: ",proc.wait())
