{
  description = "Sudoku shellcode puzzle";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  outputs = { nixpkgs, ... }:
    let
      pkgs = nixpkgs.legacyPackages.x86_64-linux;
    in
    {
      devShells.x86_64-linux.default = pkgs.mkShell {
        packages = [ pkgs.python3 pkgs.uv pkgs.nasm ];
        env = {
          UV_PYTHON = "${pkgs.python3}/bin/python3";
          UV_PYTHON_DOWNLOADS = "never";
          # Native libraries for manylinux wheels pulled in with `uv add`.
          LD_LIBRARY_PATH = pkgs.lib.makeLibraryPath [ pkgs.stdenv.cc.cc.lib pkgs.zlib ];
        };
        shellHook = ''
          [ -d .venv ] || uv sync --quiet
          source .venv/bin/activate
        '';
      };
    };
}
