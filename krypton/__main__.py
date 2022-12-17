import argparse
import shutil
import pathlib
import sys
from . import configs

def cleanDatabase():
    configs.SQLDefaultCryptoDBpath = "sqlite+pysqlite://"
    configs.SQLDefaultUserDBpath = "sqlite+pysqlite://"
    configs.SQLDefaultKeyDBpath = "sqlite+pysqlite://"
    KR_DATA = pathlib.Path(pathlib.Path.home(), ".krptn-data/")
    if KR_DATA.exists():
        shutil.rmtree(KR_DATA.as_posix())

parser = argparse.ArgumentParser(description='Krptn CLI')
parser.add_argument('--clean', dest="doAction", const=cleanDatabase, nargs='?',
    default=lambda: "Not cleaning Krptn database", help='Clean Krptn\'s default database (.krptn-data)')
args = parser.parse_args(sys.argv[1:])
args.doAction()
