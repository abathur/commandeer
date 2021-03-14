{ pkgs ? import <nixpkgs> { }
  # cmdcat isn't building on darwin at this commit, see below for more
  , includeCmdcat ? !pkgs.stdenv.isDarwin
}:

with pkgs;
let
  # I had to hack extensively on my local to get the latest commit
  # running on macOS. I was hoping NixOS would be easier, but it hasn't.
  # I have had better luck with the commit before last, which needs only
  # a few patches below...
  #
  # the first few macOS failures are:
  # - tests/exec-test.cc: fatal error: 'wait.h' file not found
  #   missing "environ" (iirc this is in "../lib/utils.h")
  # - bin/main.cc: missing "environ", "execvpe" (latter is definitely a cross-platform issue)
  cmdcat = stdenv.mkDerivation rec {
    pname = "cmdcat";
    version = "unreleased";
    src = fetchFromGitHub {
      # https://github.com/analyman/cmdcat
      owner  = "analyman";
      repo   = "cmdcat";
      # falling back to 1 commit before latest; the LUA change is giving me
      # too much trouble.
      rev    = "7fcde6102258e4c7dae4b9373204efefaf5fe9ed";
      hash = "sha256-fAhegDYJu+DG0T0LMip8T2U7cW6+Sj6Vr29Q5EUyZTs=";
      # latest is:
      # rev  = "3bfa93521bafc62e3d201ee5d07e1fb281f33e92";
      # hash = "sha256-sUF0AxiNP70TX2DVzcuwlAqQyPWac/zXxbO/C2jdMTA=";
    };

    # don't trust me much from here on out; I've done a lot of fiddling/fumbling.
    # I don't know exactly what I'm doing, and I haven't tried to clean it up yet
    # since I haven't gotten it working.

    nativeBuildInputs = [ cmake pkgconfig ];
    buildInputs = with pkgs; [
      # cmdcat source has this in a submodule @ third_party/json
      nlohmann_json
      # I had trouble with a signature mismatch using default lua
      # don't recall for sure but I think it was 5.1?
      # lua5_3 temp disabled; using commit before lua support is lit up
    ];
    patchPhase = ''
    patchShebangs tests
    # find nixpkgs copy instead of vendored
    substituteInPlace CMakeLists.txt --replace "add_subdirectory(./third_party/json)" "find_package(nlohmann_json REQUIRED)"
    # cross platform
    substituteInPlace bin/main.cc --replace "libccat.so" "libccat${stdenv.hostPlatform.extensions.sharedLibrary}"
    # modify one entry in hardcoded search path to help it find libccat
    # this is not at all ideal; would be better as a patch or upstreamed
    substituteInPlace bin/main.cc --replace "/usr/local/lib" "$out/lib"
    '';

    installPhase = ''
      # just dumping find for debug; kill later
      find .
      mkdir -p $out/bin $out/lib
      install cmdcat $out/bin
      install lib/libccat${stdenv.hostPlatform.extensions.sharedLibrary} $out/lib
    '';
    checkPhase = ''
      cp ../tests/test.sh tests/test.sh
      tests/test.sh
    '';
    doCheck = true;
    extraOutputsToInstall = [ "lib" ];
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

    nativeBuildInputs = [ cmake pkgconfig clang ];
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
    version = "3.3.2";
    src = python3.pkgs.fetchPypi {
      inherit pname version;
      hash = "sha256-SwhyB2BWMM3EZ/nz56IEIGIXsJjuRiiUoUF5+WxA46Q=";
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
  buildInputs = [ clade red ] ++ stdenv.lib.optionals includeCmdcat [ cmdcat ];
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
    bat --paging never --wrap never ./pstree_egrep_xargs_echo.sh

    printf "\033[33m============================= red demo ===============================\033[0m\n"
    echo "running: ${red}/bin/red -o /dev/fd/1 ./pstree_egrep_xargs_echo.sh"
    echo Note: red is built on Bear and wants to write to compile_commands.json by default.
    time ${red}/bin/red -o /dev/fd/1 ./pstree_egrep_xargs_echo.sh
    # time main.sh ./pstree_egrep_xargs_echo.sh
    echo ""

    printf "\033[33m============================= clade demo ===============================\033[0m\n"
    echo "running: ${clade}/bin/clade -i -f ./pstree_egrep_xargs_echo.sh"
    echo Note: clade writes to clade/cmds.txt. It recommands consuming the format via it\'s python processor API since it might change...
    time ${clade}/bin/clade -i -f ./pstree_egrep_xargs_echo.sh
    bat --paging never --wrap never clade/cmds.txt
    echo wat?
  '' + stdenv.lib.optionalString includeCmdcat ''
    printf "\033[33m============================= cmdcat demo ===================================\033[0m\n"
    echo "running: ${cmdcat}/bin/cmdcat ./pstree_egrep_xargs_echo.sh"
    time ${cmdcat}/bin/cmdcat ./pstree_egrep_xargs_echo.sh
  '';
}
