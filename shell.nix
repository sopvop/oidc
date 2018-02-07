{ pkgs ? import ./../smassetman-server/pkgs.nix {} }:
let
  p = pkgs.haskellPackages.callCabal2nix "oidc" ./. {};

in p.env
