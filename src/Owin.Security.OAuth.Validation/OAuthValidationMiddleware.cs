/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/aspnet-contrib/AspNet.Security.OAuth.Extensions for more information
 * concerning the license and the contributors participating to this project.
 */

using System;
using JetBrains.Annotations;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.Logging;
using Microsoft.Owin;
using Microsoft.Owin.BuilderProperties;
using Microsoft.Owin.Security.Infrastructure;
using Microsoft.Owin.Security.Interop;

namespace Owin.Security.OAuth.Validation {
    public class OAuthValidationMiddleware : AuthenticationMiddleware<OAuthValidationOptions> {
        public OAuthValidationMiddleware(
            [NotNull] OwinMiddleware next,
            [NotNull] IAppBuilder app,
            [NotNull] OAuthValidationOptions options)
            : base(next, options) {
            if (Options.Events == null) {
                Options.Events = new OAuthValidationEvents();
            }

            if (options.DataProtectionProvider == null) {
                // Try to use the application name provided by
                // the OWIN host as the application discriminator.
                var discriminator = new AppProperties(app.Properties).AppName;

                // When an application discriminator cannot be resolved from
                // the OWIN host properties, generate a temporary identifier.
                if (string.IsNullOrEmpty(discriminator)) {
                    discriminator = Guid.NewGuid().ToString();
                }

                options.DataProtectionProvider = DataProtectionProvider.Create(discriminator);
            }

            if (options.AccessTokenFormat == null) {
                // Note: the following purposes must match the ones used by ASOS.
                var protector = options.DataProtectionProvider.CreateProtector(
                    "OpenIdConnectServerMiddleware", "ASOS", "Access_Token", "v1");

                options.AccessTokenFormat = new AspNetTicketDataFormat(new DataProtectorShim(protector));
            }

            if (options.Logger == null) {
                options.Logger = new LoggerFactory().CreateLogger<OAuthValidationMiddleware>();
            }
        }

        protected override AuthenticationHandler<OAuthValidationOptions> CreateHandler() {
            var instance = Options.Handler?.Invoke();
            return instance ?? new OAuthValidationHandler();
        }
    }
}
