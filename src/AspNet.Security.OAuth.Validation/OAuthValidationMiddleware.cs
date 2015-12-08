/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/aspnet-contrib/AspNet.Security.OAuth.Extensions for more information
 * concerning the license and the contributors participating to this project.
 */

using System.Text.Encodings.Web;
using Microsoft.AspNet.Authentication;
using Microsoft.AspNet.DataProtection;
using Microsoft.AspNet.Http;
using Microsoft.Extensions.Internal;
using Microsoft.Extensions.Logging;

namespace AspNet.Security.OAuth.Validation {
    public class OAuthValidationMiddleware : AuthenticationMiddleware<OAuthValidationOptions> {
        public OAuthValidationMiddleware(
            [NotNull] RequestDelegate next,
            [NotNull] OAuthValidationOptions options,
            [NotNull] ILoggerFactory loggerFactory,
            [NotNull] UrlEncoder encoder,
            [NotNull] IDataProtectionProvider dataProtectionProvider)
            : base(next, options, loggerFactory, encoder) {
            if (options.TicketFormat == null) {
                // Note: the purposes of the default ticket
                // format must match the values used by ASOS.
                options.TicketFormat = new TicketDataFormat(
                    dataProtectionProvider.CreateProtector(
                        "AspNet.Security.OpenIdConnect.Server.OpenIdConnectServerMiddleware",
                        "oidc-server", "Access_Token", "v1"));
            }
        }

        protected override AuthenticationHandler<OAuthValidationOptions> CreateHandler() {
            return new OAuthValidationHandler();
        }
    }
}
