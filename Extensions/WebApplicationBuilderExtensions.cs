using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Mrbr.Service.KeyManager.Configuration;
using Mrbr.Service.KeyManager.Services;

namespace Mrbr.Service.KeyManager.Extensions;
public static class WebApplicationBuilderExtensions {
    //public static WebApplicationBuilder LoadKeyServiceConfiguration(this WebApplicationBuilder builder) {
    //    //builder.Services.AddOptions<KeyServiceConfig>()
    //    //    .Bind(builder.Configuration.GetSection(nameof(KeyService)));
    //    //var keyConfigurationOptions = builder.Services.BuildServiceProvider().GetRequiredService<IOptions<KeyServiceConfig>>();
    //    //KeyService.Initialise(keyConfigurationOptions.Value);
    //    return builder;
    //}
}