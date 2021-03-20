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
  name = "commandeer-shell";
  src = ./.;
  installPhase = ''
    mkdir $out
  '';
  doCheck = true;
  buildInputs = [ ief ouryara gnugrep binutils-unwrapped file bingrep gotools asmfmt fzf go gofumpt jmespath shfmt yaml2json zsh ]; # +nm from bintools
}
