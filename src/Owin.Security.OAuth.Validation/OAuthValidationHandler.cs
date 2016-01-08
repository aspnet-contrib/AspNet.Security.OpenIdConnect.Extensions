/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/aspnet-contrib/AspNet.Security.OAuth.Extensions for more information
 * concerning the license and the contributors participating to this project.
 */

using System;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.Owin.Logging;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Infrastructure;

namespace Owin.Security.OAuth.Validation {
    public class OAuthValidationHandler : AuthenticationHandler<OAuthValidationOptions> {
        protected override async Task<AuthenticationTicket> AuthenticateCoreAsync() {
            var header = Request.Headers.Get("Authorization");
            if (string.IsNullOrEmpty(header)) {
                Options.Logger.WriteVerbose("Authentication was skipped because no bearer token was received.");

                return null;
            }

            // Ensure that the authorization header contains the mandatory "Bearer" scheme.
            // See https://tools.ietf.org/html/rfc6750#section-2.1
            if (!header.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase)) {
                Options.Logger.WriteWarning("Authentication failed because an invalid scheme " +
                                            "was used in the 'Authorization' header.");

                return null;
            }

            var token = header.Substring("Bearer ".Length);
            if (string.IsNullOrWhiteSpace(token)) {
                Options.Logger.WriteWarning("Authentication failed because the bearer token " +
                                            "was missing from the 'Authorization' header.");

                return null;
            }

            // Try to unprotect the token and return an error
            // if the ticket can't be decrypted or validated.
            var ticket = Options.TicketFormat.Unprotect(token);
            if (ticket == null) {
                Options.Logger.WriteWarning("Authentication failed because the access token was invalid.");

                return null;
            }

            // Ensure that the access token was issued
            // to be used with this resource server.
            if (!await ValidateAudienceAsync(ticket)) {
                Options.Logger.WriteWarning("Authentication failed because the access token " +
                                            "was not valid for this resource server.");

                return null;
            }

            // Ensure that the authentication ticket is still valid.
            if (ticket.Properties.ExpiresUtc.HasValue &&
                ticket.Properties.ExpiresUtc.Value < Options.SystemClock.UtcNow) {
                Options.Logger.WriteWarning("Authentication failed because the access token was expired.");

                return null;
            }

            return ticket;
        }

        protected virtual Task<bool> ValidateAudienceAsync(AuthenticationTicket ticket) {
            // If no explicit audience has been configured,
            // skip the default audience validation.
            if (Options.Audiences.Count == 0) {
                return Task.FromResult(true);
            }

            // Extract the audiences from the authentication ticket.
            string audiences;
            if (!ticket.Properties.Dictionary.TryGetValue(OAuthValidationConstants.Properties.Audiences, out audiences)) {
                return Task.FromResult(false);
            }

            // Ensure that the authentication ticket contains the registered audience.
            if (!audiences.Split(' ').Intersect(Options.Audiences, StringComparer.Ordinal).Any()) {
                return Task.FromResult(false);
            }

            return Task.FromResult(true);
        }
    }
}
