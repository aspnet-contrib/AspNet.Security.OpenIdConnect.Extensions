/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/aspnet-contrib/AspNet.Security.OAuth.Extensions for more information
 * concerning the license and the contributors participating to this project.
 */

using System.Text.Encodings.Web;
using JetBrains.Annotations;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace AspNet.Security.OAuth.Validation {
    public class OAuthValidationMiddleware : AuthenticationMiddleware<OAuthValidationOptions> {
        public OAuthValidationMiddleware(
            [NotNull] RequestDelegate next,
            [NotNull] IOptions<OAuthValidationOptions> options,
            [NotNull] ILoggerFactory loggerFactory,
            [NotNull] UrlEncoder encoder,
            [NotNull] IDataProtectionProvider dataProtectionProvider)
            : base(next, options, loggerFactory, encoder) {
            if (Options.TicketFormat == null) {
                // Note: the purposes of the default ticket
                // format must match the values used by ASOS.
                Options.TicketFormat = new TicketDataFormat(
                    dataProtectionProvider.CreateProtector(
                        "AspNet.Security.OpenIdConnect.Server.OpenIdConnectServerMiddleware",
                        "ASOS", "Access_Token", "v1"));
            }
        }

        protected override AuthenticationHandler<OAuthValidationOptions> CreateHandler() {
            return new OAuthValidationHandler();
        }
    }
}
