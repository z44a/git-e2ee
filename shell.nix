# Dev shell: libsignal's build scripts need protoc.
{ pkgs ? import <nixpkgs> { } }:
pkgs.mkShell {
  packages = [ pkgs.protobuf pkgs.cargo pkgs.rustc pkgs.git ];
  PROTOC = "${pkgs.protobuf}/bin/protoc";
}
