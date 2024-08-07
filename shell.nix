{ pkgs ? import <nixpkgs> {} }:

pkgs.mkShell {
  buildInputs = [
    (pkgs.go_1_20.overrideAttrs (oldAttrs: rec {
      version = "1.20.5";
      src = pkgs.fetchurl {
        url = "https://go.dev/dl/go${version}.src.tar.gz";
        sha256 = "sha256-mhXBM7os+v55ZS9IFbYufPwmf2jfG5RUxqsqPKi5aog=";
      };
    }))
  ];
}
