using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;
using Mrbr.Service.KeyManager.Services;

namespace Mrbr.Service.KeyManager.Configuration;
public static class KeyServiceConfiguration {

    /// <summary>
    /// Configures Key Service dependencies and options for the application.
    /// </summary>
    /// <param name="builder">The web application builder used to register services and bind configuration.</param>
    /// <returns>The same <see cref="WebApplicationBuilder"/> instance for fluent chaining.</returns>
    /// <remarks>
    /// This method:
    /// <list type="bullet">
    /// <item><description>Binds <see cref="KeyServiceConfig"/> to the <c>KeyService</c> configuration section.</description></item>
    /// <item><description>Registers <see cref="KeyServiceOptions"/> as a singleton.</description></item>
    /// <item><description>Registers <see cref="IKeyService"/> with <see cref="KeyService"/> as a singleton.</description></item>
    /// </list>
    /// </remarks>
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