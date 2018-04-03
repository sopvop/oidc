let
  overrides = import ./../stagex-store/packages.nix;
  base = import (import ./../stagex-store/pkgs.nix) { overlays = [overrides];};
in
{ pkgs ? base }:
let
  p = pkgs.haskellPackages.callCabal2nix "oidc" ./. {};

in p.env
