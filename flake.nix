{
	description = "Introduction to Cybersecurity Assignment";
	
	inputs.nixpkgs.url = "github:nixos/nixpkgs/nixos-unstable";
	
	outputs = { self, nixpkgs }:
		let
			systems = [
				"x86_64-linux"
				"aarch64-linux"
				"x86_64-darwin"
				"aarch64-darwin"
			];
			
			forAllSystems = nixpkgs.lib.genAttrs systems;
			
		in {
			packages = forAllSystems (system:
				let
					pkgs = import nixpkgs { inherit system; };
				in {
					default = pkgs.buildDotnetModule {
						pname = "cybersecurity-assignment";
						version = "1.0";
						
						# The application source directory.
						src = ./src;
						
						# Change this if the project file has a different name.
						projectFile = "Assignment.slnx";
						
						# This file is generated in the next step below.
						nugetDeps = ./deps.json;
						
						dotnet-sdk = pkgs.dotnetCorePackages.sdk_11_0;
						dotnet-runtime = pkgs.dotnetCorePackages.runtime_11_0;
						
						selfContainedBuild = true;

						executables = [ "App" ];
					};
				});
			
			devShells = forAllSystems (system:
				let
					pkgs = import nixpkgs {
						inherit system;
					};
				in {
					default = pkgs.mkShell {
						packages = [
							pkgs.dotnetCorePackages.sdk_11_0
						];

						shellHook = ''
							echo "Cybersecurity assignment development shell"
							echo "Run: dotnet build"
						'';
					};
				});

			checks = forAllSystems (system: {
				build = self.packages.${system}.default;
			});
		};
}

