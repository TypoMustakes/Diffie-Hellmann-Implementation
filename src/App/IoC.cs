using Microsoft.Extensions.DependencyInjection;
using Network;
using Logic;

namespace App;

public static class IoC
{
	public static ServiceProvider Build()
	{
		var services = new ServiceCollection();
		
		RegisterServices(services);
		
		return services.BuildServiceProvider(
			new ServiceProviderOptions
			{
				ValidateScopes = true,
				ValidateOnBuild = true
			});
	}
	
	private static void RegisterServices(IServiceCollection services)
	{
		services.AddSingleton<IPeerToPeerService, PeerToPeerService>();
		services.AddSingleton<IHkdf, Hkdf>();
		services.AddSingleton<IAesCrypto, AesCrypto>();
		services.AddSingleton<IDhKeyExchange, DhKeyExchange>();
		services.AddSingleton<IParameterGenerator, ParameterGenerator>();
	}
}
