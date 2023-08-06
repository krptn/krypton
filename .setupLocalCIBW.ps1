$Env:CIBW_ARCHS="x86_64"
$Env:CIBW_BEFORE_ALL="yum install -y curl zip unzip tar
chmod a+x vcpkg/bootstrap-vcpkg.sh
./vcpkg/bootstrap-vcpkg.sh

./vcpkg/vcpkg install --triplet x64-linux"
$Env:CIBW_PLATFORM="linux"
$Env:CIBW_TEST_SKIP="pp*"
$Env:CIBW_BUILD_VERBOSITY=3