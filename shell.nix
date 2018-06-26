let
  overrides = import ./../stagex-store/packages.nix;

  oidcPkgs = self: super: {
     haskellPackages = super.haskellPackages.extend (pself: psuper: {
         oidc = psuper.callCabal2nix "oidc" ./oidc {};
     });
  };

  base = import (import ./../stagex-store/pkgs.nix) {
    overlays = [overrides oidcPkgs];
  };

in
{ pkgs ? base }:
let

in
  base.haskellPackages.shellFor {
    packages = p: [ p.oidc ];
  }
