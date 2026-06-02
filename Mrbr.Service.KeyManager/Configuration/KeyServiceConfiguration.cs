using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;
using Mrbr.Service.KeyManager.Services;

namespace Mrbr.Service.KeyManager.Configuration;
public static class KeyServiceConfiguration {
    public static WebApplicationBuilder ConfigureKeyService(this WebApplicationBuilder builder) {
        var services = builder.Services;
        services
            .AddOptions<KeyServiceConfig>()
            .Bind(builder.Configuration.GetSection(nameof(KeyService)));

        services.AddSingleton<KeyServiceOptions>();
        services.AddSingleton<IKeyService, KeyService>();
        return builder;
    }
}