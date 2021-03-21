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
  # jdk: fop
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
    check_ief(){
      for func in execl execle execlp exect execv execve execveat execvp execvP execvpe fexecve posix_spawn posix_spawnp system; do
        if [[ "$(ief $1 -i $func)" == *"$1"$'\n'"$1" ]] || [[ "$(ief $1 -i _$func)" == *"$1"$'\n'"$1" ]]; then
          return 0
        fi
      done
      return 1
    }
    check_binary_for_functions(){
      local binary="$1" func="$2"
      printf "%s contains %s: " "$binary" "$func"
      if grep -F -e execl -e execle -e execlp -e exect -e execv -e execve -e execveat -e execvp -e execvP -e execvpe -e fexecve -e posix_spawn -e posix_spawnp -e system "$binary" >/dev/null; then
        printf "grep: yes; "
      else
        printf "grep: no; "
      fi
      if check_ief $binary; then
        printf "ief: yes; "
      else
        printf "ief: no; "
      fi
      if nm --dynamic --undefined "$binary" 2>/dev/null | grep -F -e "U execl" -e "U execle" -e "U execlp" -e "U exect" -e "U execv" -e "U execve" -e "U execveat" -e "U execvp" -e "U execvP" -e "U execvpe" -e "U fexecve" -e "U posix_spawn" -e "U posix_spawnp" -e "U system" -e "U _execl" -e "U _execle" -e "U _execlp" -e "U _exect" -e "U _execv" -e "U _execve" -e "U _execveat" -e "U _execvp" -e "U _execvP" -e "U _execvpe" -e "U _fexecve" -e "U _posix_spawn" -e "U _posix_spawnp" -e "U _system" >/dev/null; then
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
        check_binary_for_functions "$binary" "exec"
      done
    done >> checklog
    cat checklog
    set -x
    grep -c "contains exec: .*grep: yes.*ief: yes" checklog || true
    grep -c "contains exec: .*grep: yes.*ief: no" checklog || true
    grep -c "contains exec: .*grep: no.*ief: yes" checklog || true
    grep -c "contains exec: .*grep: no.*ief: no" checklog || true
    grep -c "contains exec: .*ief: yes; nm: yes" checklog || true
    grep -c "contains exec: .*ief: yes; nm: no" checklog || true
    grep -c "contains exec: .*ief: no; nm: yes" checklog || true
    grep -c "contains exec: .*ief: no; nm: no" checklog || true
    grep -c "contains exec: .*ief: yes;.*yara: yes" checklog || true
    grep -c "contains exec: .*ief: yes;.*yara: no" checklog || true
    grep -c "contains exec: .*ief: no;.*yara: yes" checklog || true
    grep -c "contains exec: .*ief: no;.*yara: no" checklog || true
    set +x
  '';
}
