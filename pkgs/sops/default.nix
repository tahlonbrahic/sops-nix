{
  sops,
  fetchFromGitHub,
}:
sops.overrideAttrs {
  version = "sops";

  src = fetchFromGitHub {
    owner = "age-sops";
    repo = "sops";
    rev = "a891aaa1707d9ac2586bc5b0984e3bce60e084cc";
    hash = "sha256-wFGFq6EoRYh8kD8ZELKATsitHEB0uz4/IBZL4+L0U1A=";
  };

  vendorHash = "sha256-B6g5xvPNGQzmQNHC09CTMnc5PrESYKiVNJTuy9eIhTs=";

  installCheckPhase = "";
  versionCheckPhase = "";
}
