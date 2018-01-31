{ pkgs ? import <nixpkgs> {} }:
let
  p = pkgs.haskellPackages.callCabal2nix "oidc" ./. {};

in p.env
