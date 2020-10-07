{ pkgs ? import <nixpkgs> { }
}:

with pkgs;
let
  # I've had to hack extensively on my local; I'm hoping maybe it'll run on linux
  # in CI with minimal mods; I'll be progressively enabling patches below if not
  cmdcat = stdenv.mkDerivation rec {
    pname = "cmdcat";
    version = "unreleased";
    # https://github.com/analyman/cmdcat
    src = fetchFromGitHub {
      owner  = "analyman";
      repo   = "cmdcat";
      rev    = "3bfa93521bafc62e3d201ee5d07e1fb281f33e92";
      hash = "sha256-sUF0AxiNP70TX2DVzcuwlAqQyPWac/zXxbO/C2jdMTA=";
    };

    nativeBuildInputs = [ cmake pkgconfig gcc fixDarwinDylibNames ];
    buildInputs = with pkgs; [ nlohmann_json lua5_3 ];
    # patchPhase = ''
    #   substituteInPlace CMakeLists.txt --replace "add_subdirectory(./third_party/json)" "find_package(nlohmann_json REQUIRED)"
    #   substituteInPlace tests/exec-test.cc --replace "<wait.h>" "<sys/wait.h>"
    #   substituteInPlace bin/main.cc --replace "libccat.so" "libccat${stdenv.hostPlatform.extensions.sharedLibrary}"
    #   grep libccat bin/main.cc
    # '';
    # cmakeFlags = [
    #   "-DCMAKE_CXX_COMPILER=${gcc}/bin/g++"
    #   "-DCMAKE_C_COMPILER=${gcc}/bin/gcc"
    #   "-DLUA_LIBRARY=${lua5_3}/lib/liblua${stdenv.hostPlatform.extensions.sharedLibrary}"
    # ];
    # configureFlags = [
    #   "CPPFLAGS=-I${nlohmann_json}/include/nlohmann/"
    #   "-Dnlohmann_json_DIR=${nlohmann_json}/lib/cmake/nlohmann_json"
    # ];
    # installPhase = ''
    #   find .
    #   mkdir -p $out/bin $out/lib
    #   install cmdcat $out/bin
    #   install lib/libccat.dylib $out/lib
    # '';
    # checkPhase = ''
    #   cp $src/tests/test.sh tests/test.sh
    #   tests/test.sh
    # '';
    # doCheck = true;
    # extraOutputsToInstall = [ "lib" ];
  };
  red = stdenv.mkDerivation rec {
    pname = "red";
    version = "unreleased";
    # this still has Bear/libEAR cruft in it...
    src = fetchFromGitHub {
      owner = "karkhaz";
      repo = "red";
      rev = "6c18838a7cb0cf8056bff5ff0dcf3b3baa51a76e";
      hash = "sha256-BowniihNi4fKTwNP8akvTZyhLQNvvXDn7Lm1SSxzVNg=";
    };

    nativeBuildInputs = [ cmake pkgconfig clang fixDarwinDylibNames ];
    buildInputs = with pkgs; [ ];
    # says >=2.7; I started with 2.7 since that's already in resholve's closure...
    propagatedBuildInputs = [ python27 ];
    patchPhase = ''
      # obviously missing on macOS; also, it's still got a plain <unistd.h> include.
      # maybe a mistake? maybe meant to have ifdef logic to pick?
      substituteInPlace libred/red.c --replace "#include <linux/unistd.h>" ""
      # these aren't compiling on macOS and a brief search didn't turn up an obvious fix
      substituteInPlace libred/red.c --replace "__THROW __attribute ((__noreturn__))" ""
    '';
  };
  clade = python3.pkgs.buildPythonPackage rec {
    pname = "clade";
    version = "3.2.12";
    src = python3.pkgs.fetchPypi {
      inherit pname version;
      hash = "sha256-XK0Ohr5C0gSF1VJCKs1qhw4IUDFgmiPJyVKg+mhLmRo=";
    };
    dontUseCmakeConfigure = true;
    doCheck = false;
    nativeBuildInputs = [ clang python3 cmake ];
    propagatedBuildInputs = with python3.pkgs; [ ujson chardet cchardet graphviz ply setuptools pip ];
  };

in stdenv.mkDerivation {
  name = "commandeer-ci";
  src = ./.;
  installPhase = ''
    mkdir $out
  '';
  doCheck = true;
  buildInputs = [ clade red ] ++ stdenv.lib.optionals stdenv.isLinux [ cmdcat ];
  # TODO: add pstree to the list of programs with unspecified deps; it invokes a bare
  # ps and *WILL* fail if ps isn't on path.
  checkInputs = [ ps pstree findutils gnugrep bat ]; # bat just for formatting...

    # mkdir $out
    # cp ./pstree_egrep_xargs_echo.sh $out/
    # echo "#!/usr/bin/env bash" > $out/sigh.sh
    # chmod 777 $out/sigh.sh
    # cd $out
  checkPhase = ''
    patchShebangs .
    printf "\033[33m============================= test script ===================================\033[0m\n"
    bat ./pstree_egrep_xargs_echo.sh

    printf "\033[33m============================= red demo ===============================\033[0m\n"
    echo "running: ${red}/bin/red -o /dev/fd/1 ./pstree_egrep_xargs_echo.sh"
    echo Note: red is built on Bear and wants to write to compile_commands.json by default.
    ${red}/bin/red -o /dev/fd/1 ./pstree_egrep_xargs_echo.sh
    echo ""

    printf "\033[33m============================= clade demo ===============================\033[0m\n"
    echo "running: ${clade}/bin/clade -i -f ./pstree_egrep_xargs_echo.sh"
    echo Note: clade writes to clade/cmds.txt. It recommands consuming the format via it\'s python processor API since it might change...
    ${clade}/bin/clade -i -f ./pstree_egrep_xargs_echo.sh
    bat --paging never --wrap never clade/cmds.txt
    echo wat?
  '' + stdenv.lib.optionalString stdenv.isLinux ''
    printf "\033[33m============================= cmdcat demo ===================================\033[0m\n"
    echo "running: ${cmdcat}/bin/cmdcat ./pstree_egrep_xargs_echo.sh"
    ${cmdcat}/bin/cmdcat ./pstree_egrep_xargs_echo.sh
  '';
}
