{ pkgs ? import <nixpkgs> { }
}:

with pkgs;
let
  ief = rustPlatform.buildRustPackage rec {
    pname = "ief";
    version = "9529fde287602db14864a107bfa0bf308caded6a";

    src = fetchFromGitHub {
      owner = "abathur";
      repo = pname;
      rev = version;
      hash = "sha256-6l7r+7uWzt/2JEdMJThHCjjRbFPn1WY4rYHtZ4wgVH4=";
    };

    cargoHash = "sha256-2yAyFCI1WuQ8e5xIyLKJg5kNh9VdF6FH4RlWYUw8dVs=";

    buildInputs = [ libiconv ];
  };
  # override for macho and elf module improvements
  ouryara = yara.overrideAttrs(old: rec {
    version = "4.1.0-rc1";

    src = fetchFromGitHub {
      owner = "VirusTotal";
      repo = "yara";
      rev = "v${version}";
      hash = "sha256-7STiGsDwD/p2+Bxnt5rFeJ+/mpJAcVdPh15+cTM2uG4=";
    };
    configureFlags = old.configureFlags ++ [ (lib.enableFeature true "macho") ];
    patches = [];
  });

in stdenv.mkDerivation rec {
  /*
  Goal for this test is to:
  1. throw in a bunch of "commands"
  2. use multiple approaches to audit the commands for whether they ~exec
  3. compare accuracy

  I am also interested in performance, but I'm going to resist the
  temptation to focus on it yet; these tools work at different
  granularities and comparing accuracy will be at odds with getting
  performance numbers that reflect how I would end up using the tools
  */
  name = "commandeer-static";
  src = ./.;
  installPhase = ''
    mkdir $out
  '';
  doCheck = true;
  buildInputs = [ ief ouryara gnugrep binutils-unwrapped file ]; # +nm from bintools
  # ocaml: satysfi
  # jdk: fop diffoscope ipscan
  CHECKPATH = "${lib.makeBinPath (buildInputs ++ [ antlr
asmfmt
bandwhich
bash
bashInteractive
bat
bazel
bc
bingrep
bison
brotli
bup
bzip2
cargo
clang
cmake
coloursum
coreutils
cowsay
curl
dash
deno
# diffoscope # e2fsprogs marked broken
diffutils
doxygen
ed
emacs
exa
ffmpeg
findutils
fish
fop
fzf
gawk
gcc
git
gmp
gnugrep
gnumake
gnupatch
gnupg
gnused
go
gofumpt
gotools
gzip
htop
hugo
icestorm
# ipscan # marked broken
jekyll
jmespath
jq
less
libffi
llvm
loc
lsof
lynx
man
more
ncurses
ninja
nmap
nodejs
openssh
openvpn
p7zip
pass
patch
patchutils
pcre
perl
php
ponyc
ps
pstree
python
ripgrep
rsync
rustc
rustfmt
sass
satysfi
shellcheck
shfmt
smenu
textql
time
tmate
tmux
unzip
vault
vim
xz
yacc
yaml2json
zlib
zsh ] ++ stdenv.lib.optionals (!stdenv.isDarwin) [ sudo ])}";
  # propagatedBuildInputs = [ pyEnv ];

    # mkdir $out
    # cp ./pstree_egrep_xargs_echo.sh $out/
    # echo "#!/usr/bin/env bash" > $out/sigh.sh
    # chmod 777 $out/sigh.sh
    # cd $out
    # ${bashInteractive}/bin/bash -c "shopt -s progcomp; ${coreutils}/bin/comm -23 <(compgen -A command | ${coreutils}/bin/sort) <(compgen -A builtin -A function -A keyword | ${coreutils}/bin/sort) | ${findutils}/bin/xargs ${which}/bin/which -a | ${coreutils}/bin/sort -u"
  checkPhase = ''
    commands(){
      ${bashInteractive}/bin/bash -c "shopt -s progcomp; ${coreutils}/bin/comm -23 <(compgen -A command | ${coreutils}/bin/sort) <(compgen -A builtin -A function -A keyword | ${coreutils}/bin/sort -u)"
    }
    check_binary_for_function(){
      local binary="$1" func="$2"
      printf "%s contains %s: " "$binary" "$func"
      if grep -F "''${func/_/@_}" "$binary" >/dev/null; then
        printf "grep: yes; "
      else
        printf "grep: no; "
      fi
      if [[ "$(ief $binary -i $func)" == *"$binary"$'\n'"$binary" ]]; then
        printf "ief: yes; "
      else
        printf "ief: no; "
      fi
      if nm --dynamic --undefined "$binary" 2>/dev/null | grep -F "U $func" >/dev/null; then
        printf "nm: yes; "
      else
        printf "nm: no; "
      fi
      if yara rule.yar "$binary" 2>/dev/null | grep -F "Texecve $binary" >/dev/null; then
        printf "yara: yes; "
      else
        printf "yara: no; "
      fi
      printf "\n"
    }
    yara rule.yar --scan-list <(echo -e ''${CHECKPATH//:/\\n})
    PATH="$CHECKPATH"
    for cmd in $(commands); do
      for binary in $(type -ap $cmd | sort -u); do
        file --dereference "$binary"
        check_binary_for_function "$binary" "_execve"
        check_binary_for_function "$binary" "execve"
      done
    done >> checklog
    cat checklog
    set -x
    grep -c "contains execve: .*grep: yes.*ief: yes" checklog || true
    grep -c "contains execve: .*grep: yes.*ief: no" checklog || true
    grep -c "contains execve: .*grep: no.*ief: yes" checklog || true
    grep -c "contains execve: .*grep: no.*ief: no" checklog || true
    grep -c "contains execve: .*ief: yes; nm: yes" checklog || true
    grep -c "contains execve: .*ief: yes; nm: no" checklog || true
    grep -c "contains execve: .*ief: no; nm: yes" checklog || true
    grep -c "contains execve: .*ief: no; nm: no" checklog || true
    grep -c "contains execve: .*ief: yes;.*yara: yes" checklog || true
    grep -c "contains execve: .*ief: yes;.*yara: no" checklog || true
    grep -c "contains execve: .*ief: no;.*yara: yes" checklog || true
    grep -c "contains execve: .*ief: no;.*yara: no" checklog || true

    grep -c "contains _execve: .*grep: yes.*ief: yes" checklog || true
    grep -c "contains _execve: .*grep: yes.*ief: no" checklog || true
    grep -c "contains _execve: .*grep: no.*ief: yes" checklog || true
    grep -c "contains _execve: .*grep: no.*ief: no" checklog || true
    grep -c "contains _execve: .*ief: yes; nm: yes" checklog || true
    grep -c "contains _execve: .*ief: yes; nm: no" checklog || true
    grep -c "contains _execve: .*ief: no; nm: yes" checklog || true
    grep -c "contains _execve: .*ief: no; nm: no" checklog || true
    grep -c "contains _execve: .*ief: yes;.*yara: yes" checklog || true
    grep -c "contains _execve: .*ief: yes;.*yara: no" checklog || true
    grep -c "contains _execve: .*ief: no;.*yara: yes" checklog || true
    grep -c "contains _execve: .*ief: no;.*yara: no" checklog || true
    set +x
  '';
}
