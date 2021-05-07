import pathlib
from setuptools import setup

# The directory containing this file
HERE = pathlib.Path(__file__).parent

# The text of the README file
README = (HERE / "README.md").read_text()

# This call to setup() does all the work
setup(
    name="PySec",
    version="1.0.0",
    description="PySec",
    long_description=README,
    long_description_content_type="text/markdown",
    url="https://github.com/mbs9/PySec",
    license="Apache 2.0",
    packages=["PySec"],
    include_package_data=True,
    install_requires=["pyaes"],
)