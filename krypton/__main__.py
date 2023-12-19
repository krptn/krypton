import argparse
import sys
from . import configs, Base


def cleanDatabase():
    Base.metadata.drop_all(configs._cryptoDbEngine)
    Base.metadata.drop_all(configs._altKeyDbEngine)
    Base.metadata.drop_all(configs._userDbEngine)
    print("Cleaning Database completed!")


parser = argparse.ArgumentParser(description="Krptn CLI")
parser.add_argument(
    "--clean",
    dest="doAction",
    const=cleanDatabase,
    nargs="?",
    default=lambda: "Not cleaning Krptn database",
    help="Clean Krptn's default database (.krptn-data)",
)
if __name__ == "__main__":
    args = parser.parse_args(sys.argv[1:])
    args.doAction()
