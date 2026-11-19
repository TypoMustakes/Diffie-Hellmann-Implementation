# Cybersecurity Assignment

This repository contains a .NET 10 application organized into multiple projects.

## Requirements

The application targets .NET 10.

You can run it either:

- with Nix, using the reproducible environment defined by `flake.nix`; or
- by building from source with the .NET SDK installed on your system.

## Option 1: Run with Nix

Nix provides the .NET SDK, runtime, and NuGet dependencies used by the project. This is the recommended option if the application does not build or run correctly using your locally installed .NET SDK, or if you don't want to install them just for this one project.

[Install Nix](https://nixos.org/download) with flakes enabled. 

### Run directly from GitHub

Run:
```
nix run github:TypoMustakes/Diffie-Hellmann-Implementation
```

This is the easiest method to run the project reproducibly

### Run locally

Clone the repository to your machine, and enter the project root

```
git clone https://github.com/TypoMustakes/Diffie-Hellmann-Implementation.git
cd Diffie-Hellmann-Implementation
```

Then, from the project root, run:

```bash
nix run
```

### Notes
- On Windows, the Nix workflow should be run through a Linux environment such as WSL2.
- If Nix is installed but flakes are not enabled, enable them by adding the following to `~/.config/nix/nix.conf`:
```
experimental-features = nix-command flakes
```

## Option 2: Build without Nix

[Install .NET SDK 10](https://dotnet.microsoft.com/en-us/download/dotnet/10.0)

Clone the repository to your machine, and enter the project root

```
git clone https://github.com/TypoMustakes/Diffie-Hellmann-Implementation.git
cd Diffie-Hellmann-Implementation
```

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
