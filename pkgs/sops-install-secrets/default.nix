{
  lib,
  buildGoModule,
  stdenv,
  go,
  vendorHash,
  ...
}:
buildGoModule {
  pname = "sops-install-secrets";
  version = "0.0.1";

  src = lib.sourceByRegex ../.. [
    "vendor"
    "go\.(mod|sum)"
    "pkgs"
    "pkgs/sops-install-secrets.*"
  ];

  proxyVendor = false;

  subPackages = ["pkgs/sops-install-secrets"];

  #buildFlags = ["-mod=readonly"];

  # requires root privileges for tests
  doCheck = false;

  outputs = ["out"] ++ lib.lists.optionals (stdenv.isLinux) ["unittest"];

  postInstall =
    ''
      go test -c ./pkgs/sops-install-secrets
    ''
    + lib.optionalString (stdenv.isLinux) ''
      # *.test is only tested on linux. $unittest does not exist on darwin.
      install -D ./sops-install-secrets.test $unittest/bin/sops-install-secrets.test
      # newer versions of nixpkgs no longer require this step
      if command -v remove-references-to; then
        remove-references-to -t ${go} $unittest/bin/sops-install-secrets.test
      fi
    '';

  vendorHash = "sha256-fAFr1kCkU0iLspneSCCFoPt1cJrxu3fk6gmoWaCctY4=";

  meta = with lib; {
    description = "Atomic secret provisioning based on sops";
    homepage = "https://github.com/Mic92/sops-nix";
    license = licenses.mit;
    maintainers = with maintainers; [mic92];
    platforms = platforms.linux ++ platforms.darwin;
  };
}
