{
  description = "pingw";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  outputs = { self, nixpkgs }:
    let
      systems = [ "x86_64-linux" "aarch64-linux" "aarch64-darwin" "x86_64-darwin" ];
      forAllSystems = f:
        nixpkgs.lib.genAttrs systems (system: f nixpkgs.legacyPackages.${system});
    in {
      packages = forAllSystems (pkgs: rec {
        pingw = pkgs.rustPlatform.buildRustPackage {
          pname = "pingw";
          version = "0.1.0";
          src = ./.;
          cargoHash = "sha256-/PEf31PKkE6+V/1Pr24xgYNdXFTEGvH5Nfl6ofU9IP4=";
        };
        default = pingw;
      });
    };
}
