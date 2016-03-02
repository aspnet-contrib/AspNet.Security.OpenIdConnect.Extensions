﻿/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/aspnet-contrib/AspNet.Security.OAuth.Extensions for more information
 * concerning the license and the contributors participating to this project.
 */

using System;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Logging;
using Microsoft.Net.Http.Headers;

namespace AspNet.Security.OAuth.Validation {
    public class OAuthValidationHandler : AuthenticationHandler<OAuthValidationOptions> {
        protected override async Task<AuthenticateResult> HandleAuthenticateAsync() {
            string header = Request.Headers[HeaderNames.Authorization];
            if (string.IsNullOrEmpty(header)) {
                Logger.LogDebug("Authentication was skipped because no bearer token was received.");

                return AuthenticateResult.Skip();
            }

            // Ensure that the authorization header contains the mandatory "Bearer" scheme.
            // See https://tools.ietf.org/html/rfc6750#section-2.1
            if (!header.StartsWith($"{OAuthValidationDefaults.AuthenticationScheme} ", StringComparison.OrdinalIgnoreCase)) {
                return AuthenticateResult.Fail("Authentication failed because an invalid scheme " +
                                               "was used in the 'Authorization' header.");
            }

            var token = header.Substring($"{OAuthValidationDefaults.AuthenticationScheme} ".Length);
            if (string.IsNullOrWhiteSpace(token)) {
                return AuthenticateResult.Fail("Authentication failed because the bearer token " +
                                               "was missing from the 'Authorization' header.");
            }

            // Try to unprotect the token and return an error
            // if the ticket can't be decrypted or validated.
            var ticket = Options.TicketFormat.Unprotect(token);
            if (ticket == null) {
                return AuthenticateResult.Fail("Authentication failed because the access token was invalid.");
            }

            // Ensure that the access token was issued
            // to be used with this resource server.
            if (!await ValidateAudienceAsync(ticket)) {
                return AuthenticateResult.Fail("Authentication failed because the access token " +
                                               "was not valid for this resource server.");
            }

            // Ensure that the authentication ticket is still valid.
            if (ticket.Properties.ExpiresUtc.HasValue &&
                ticket.Properties.ExpiresUtc.Value < Options.SystemClock.UtcNow) {
                return AuthenticateResult.Fail("Authentication failed because the access token was expired.");
            }

            return AuthenticateResult.Success(ticket);
        }

        protected virtual Task<bool> ValidateAudienceAsync(AuthenticationTicket ticket) {
            // If no explicit audience has been configured,
            // skip the default audience validation.
            if (Options.Audiences.Count == 0) {
                return Task.FromResult(true);
            }

            // Extract the audiences from the authentication ticket.
            string audiences;
            if (!ticket.Properties.Items.TryGetValue(OAuthValidationConstants.Properties.Audiences, out audiences)) {
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
