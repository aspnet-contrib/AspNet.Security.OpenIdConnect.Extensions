/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/aspnet-contrib/AspNet.Security.OAuth.Extensions for more information
 * concerning the license and the contributors participating to this project.
 */

using System;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Net.Http.Headers;

namespace AspNet.Security.OAuth.Validation {
    public class OAuthValidationHandler : AuthenticationHandler<OAuthValidationOptions> {
        protected override async Task<AuthenticateResult> HandleAuthenticateAsync() {
            // Give the application an opportunity to parse the token from a different location, adjust, or reject token
            var parseAccessTokenContext = new ParseAccessTokenContext(Context, Options);
            await Options.Events.ParseAccessToken(parseAccessTokenContext);

            // Initialize the token from the event in case it was set during the event.
            string token = parseAccessTokenContext.Token;

            // Bypass the default processing if the event handled the request parsing.
            if (!parseAccessTokenContext.Handled) {
                string header = Request.Headers[HeaderNames.Authorization];
                if (string.IsNullOrWhiteSpace(header)) {
                    return AuthenticateResult.Fail("Authentication failed because the bearer token " +
                                                   "was missing from the 'Authorization' header.");
                }

                // Ensure that the authorization header contains the mandatory "Bearer" scheme.
                // See https://tools.ietf.org/html/rfc6750#section-2.1
                if (!header.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase)) {
                    return AuthenticateResult.Fail("Authentication failed because an invalid scheme " +
                                                   "was used in the 'Authorization' header.");
                }

                token = header.Substring("Bearer ".Length);
            }

            if (string.IsNullOrWhiteSpace(token)) {
                return AuthenticateResult.Fail("Authentication failed because the bearer token " +
                                                "was missing from the request. The default location" +
                                                "is in the 'Authorization' header.");
            }

            // Try to unprotect the token and return an error
            // if the ticket can't be decrypted or validated.
            var ticket = Options.AccessTokenFormat.Unprotect(token);
            if (ticket == null) {
                return AuthenticateResult.Fail("Authentication failed because the access token was invalid.");
            }

            // Allow for interception and handling of the token validated event.
            var validateTokenContext = new ValidateTokenContext(Context, Options, ticket);
            await Options.Events.ValidateToken(validateTokenContext);

            if (validateTokenContext.Handled) {
                // Return a result based on how the validation was handled.
                return validateTokenContext.IsValid ?
                    AuthenticateResult.Success(validateTokenContext.Ticket) :
                    AuthenticateResult.Fail("Authentication failed because the access token was not valid.");
            }

            // Flow any changes that were made to the ticket during the validation event.
            ticket = validateTokenContext.Ticket;

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
