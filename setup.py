import pathlib
from setuptools import setup

# The directory containing this file
HERE = pathlib.Path(__file__).parent

# The text of the README file
README = (HERE / "README.md").read_text()

setup(
    name="PySec",
    version="1.0.0",
    description="Python Security Module",
    long_description=README,
    long_description_content_type="text/markdown",
    url="https://github.com/MBS9/PySec",
    license='BSD 3-Clause "New" or "Revised"',
    packages=["PySec"],
    include_package_data=True,
    install_requires=["pythonnet", "pyaes"],
)
