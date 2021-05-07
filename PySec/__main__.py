import _thread
import sys
def go():
    from PySec import PyToCSharp

thing = _thread.start_new_thread(go)

print("Enter quit to quit")
b=""
while b != "quit":
    b = input(">>>")

quit()