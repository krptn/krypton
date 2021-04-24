from PySec.decorators import AddSec

@AddSec
class test():
    a = "test"

b = test()

print(b.a)