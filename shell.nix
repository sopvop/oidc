let
  overrides = import ./../stagex-store/packages.nix;

  oidcPkgs = self: super: {
     haskellPackages = super.haskellPackages.extend (pself: psuper: {
         oidc = psuper.callCabal2nix "oidc" ./oidc {};
     });
  };

  pkgs = import (import ./../stagex-store/pkgs.nix) {
    overlays = [overrides oidcPkgs];
  };

  nodePackages = import oidc-web/vendor/node {
     inherit pkgs;
  };
  nodeDependencies = nodePackages.shell.nodeDependencies;
in
  pkgs.haskellPackages.shellFor {
    packages = p: [ p.oidc ];
    buildInputs = [ pkgs.sassc
                    pkgs.nodePackages.node2nix
                  ];


    shellHook =
    ''
      export NODE_PATH=${nodeDependencies}/lib/node_modules
      export PATH=$PATH:$NODE_PATH/.bin
    '';
  }
