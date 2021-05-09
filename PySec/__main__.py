import _thread
import sys
from PySec import PyToCSharp
def go():
    PyToCSharp.runner(sys.argv[1])

thing = _thread.start_new_thread(go)

print("Enter quit to quit")
b=""
while b != "quit":
    b = input(">>>")

quit()