# Cybersecurity Assignment

This repository contains a .NET 11 application organized into multiple projects.

## Requirements

The application targets .NET 11.

You can build it either:

- with Nix, using the reproducible environment defined by `flake.nix`; or
- directly with the .NET SDK installed on your system.

## Option 1: Build with Nix

Nix provides the .NET SDK, runtime, and NuGet dependencies used by the project. This is the recommended option if the application does not build or run correctly using your locally installed .NET SDK.

[Install Nix](https://nixos.org/download) with flakes enabled, then from the repository root run:

```bash
nix build
```

The executable will be under `result/bin`.

### Notes
- On Windows, the Nix workflow should be run through a Linux environment such as WSL2.
- If Nix is installed but flakes are not enabled, enable them by adding the following to `~/.config/nix/nix.conf`:
```
experimental-features = nix-command flakes
```

## Option 2: Build without Nix

[Install .NET SDK 11](https://dotnet.microsoft.com/en-us/download/dotnet/11.0)

Then, from the project root:

1. Restore dependencies:
```bash
dotnet restore src/
```

2. Build the application:
```bash
dotnet build src/
```

3. Run the application
```bash
cd src/App/
dotnet run
```
