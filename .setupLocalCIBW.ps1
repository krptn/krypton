$Env:CIBW_ARCHS="x86_64"
$Env:CIBW_BEFORE_ALL=@"
if type apk &> /dev/null; then
    apk add build-base cmake ninja zip unzip curl git
    export VCPKG_FORCE_SYSTEM_BINARIES=1
fi
if type yum &> /dev/null; then
    yum install -y curl zip unzip tar
fi
chmod a+rx vcpkg/bootstrap-vcpkg.sh
./vcpkg/bootstrap-vcpkg.sh
./vcpkg/vcpkg install --triplet x64-linux
"@
$Env:CIBW_PLATFORM="linux"
$Env:CIBW_TEST_SKIP="pp*"
$Env:CIBW_BUILD_VERBOSITY=3
$Env:CIBW_TEST_COMMAND=@"
python -m krypton --clean
python -m unittest discover -s {project}/tests -p "*test*.py" --verbose
"@
$Env:CIBW_TEST_EXTRAS="tests"
