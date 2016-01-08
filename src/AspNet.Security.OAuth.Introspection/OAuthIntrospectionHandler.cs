/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/aspnet-contrib/AspNet.Security.OAuth.Extensions for more information
 * concerning the license and the contributors participating to this project.
 */

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using Microsoft.AspNet.Authentication;
using Microsoft.AspNet.Http.Authentication;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Logging;
using Microsoft.Net.Http.Headers;
using Newtonsoft.Json.Linq;

namespace AspNet.Security.OAuth.Introspection {
    public class OAuthIntrospectionHandler : AuthenticationHandler<OAuthIntrospectionOptions> {
        protected override async Task<AuthenticateResult> HandleAuthenticateAsync() {
            string header = Request.Headers[HeaderNames.Authorization];
            if (string.IsNullOrEmpty(header)) {
                return AuthenticateResult.Fail("Authentication failed because the bearer token " +
                                               "was missing from the 'Authorization' header.");
            }

            // Ensure that the authorization header contains the mandatory "Bearer" scheme.
            // See https://tools.ietf.org/html/rfc6750#section-2.1
            if (!header.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase)) {
                return AuthenticateResult.Fail("Authentication failed because an invalid scheme " +
                                               "was used in the 'Authorization' header.");
            }

            var token = header.Substring("Bearer ".Length);
            if (string.IsNullOrWhiteSpace(token)) {
                return AuthenticateResult.Fail("Authentication failed because the bearer token " +
                                               "was missing from the 'Authorization' header.");
            }

            // Try to resolve the authentication ticket from the distributed cache. If none
            // can be found, a new introspection request is sent to the authorization server.
            var ticket = await RetrieveTicketAsync(token);
            if (ticket == null) {
                // Return a failed authentication result if the introspection
                // request failed or if the "active" claim was false.
                var payload = await GetIntrospectionPayloadAsync(token);
                if (payload == null || !payload.Value<bool>(OAuthIntrospectionConstants.Claims.Active)) {
                    return AuthenticateResult.Fail("Authentication failed because the authorization " +
                                                   "server rejected the access token.");
                }

                // Ensure that the access token was issued
                // to be used with this resource server.
                if (!await ValidateAudienceAsync(payload)) {
                    return AuthenticateResult.Fail("Authentication failed because the access token " +
                                                   "was not valid for this resource server.");
                }

                // Create a new authentication ticket from the introspection
                // response returned by the authorization server.
                ticket = await CreateTicketAsync(payload);
                Debug.Assert(ticket != null);

                await StoreTicketAsync(token, ticket);
            }

            // Ensure that the authentication ticket is still valid.
            if (ticket.Properties.ExpiresUtc.HasValue &&
                ticket.Properties.ExpiresUtc.Value < Options.SystemClock.UtcNow) {
                return AuthenticateResult.Fail("Authentication failed because the access token was expired.");
            }

            return AuthenticateResult.Success(ticket);
        }

        protected virtual async Task<string> ResolveIntrospectionEndpointAsync(string issuer) {
            if (issuer.EndsWith("/")) {
                issuer = issuer.Substring(0, issuer.Length - 1);
            }

            // Create a new discovery request containing the access token and the client credentials.
            var request = new HttpRequestMessage(HttpMethod.Get, issuer + "/.well-known/openid-configuration");
            request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));

            var response = await Options.HttpClient.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, Context.RequestAborted);
            if (!response.IsSuccessStatusCode) {
                Logger.LogError("An error occurred when retrieving the issuer metadata: the remote server " +
                                "returned a {Status} response with the following payload: {Headers} {Body}.",
                                /* Status: */ response.StatusCode,
                                /* Headers: */ response.Headers.ToString(),
                                /* Body: */ await response.Content.ReadAsStringAsync());

                return null;
            }

            var payload = JObject.Parse(await response.Content.ReadAsStringAsync());

            var address = payload[OAuthIntrospectionConstants.Metadata.IntrospectionEndpoint];
            if (address == null) {
                return null;
            }

            return (string) address;
        }

        protected virtual async Task<JObject> GetIntrospectionPayloadAsync(string token) {
            // Note: updating the options during a request is not thread safe but is harmless in this case:
            // in the worst case, it will only send multiple configuration requests to the authorization server.
            if (string.IsNullOrEmpty(Options.IntrospectionEndpoint)) {
                Options.IntrospectionEndpoint = await ResolveIntrospectionEndpointAsync(Options.Authority);
            }

            if (string.IsNullOrEmpty(Options.IntrospectionEndpoint)) {
                throw new InvalidOperationException("The OAuth2 introspection middleware was unable to retrieve " +
                                                    "the provider configuration from the OAuth2 authorization server.");
            }

            var credentials = Convert.ToBase64String(Encoding.ASCII.GetBytes($"{Options.ClientId}:{Options.ClientSecret}"));

            // Create a new introspection request containing the access token and the client credentials.
            var request = new HttpRequestMessage(HttpMethod.Post, Options.IntrospectionEndpoint);
            request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
            request.Headers.Authorization = new AuthenticationHeaderValue("Basic", credentials);

            request.Content = new FormUrlEncodedContent(new Dictionary<string, string> {
                [OAuthIntrospectionConstants.Parameters.Token] = token,
                [OAuthIntrospectionConstants.Parameters.TokenTypeHint] = OAuthIntrospectionConstants.TokenTypes.AccessToken
            });

            var response = await Options.HttpClient.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, Context.RequestAborted);
            if (!response.IsSuccessStatusCode) {
                Logger.LogError("An error occurred when validating an access token: the remote server " +
                                "returned a {Status} response with the following payload: {Headers} {Body}.",
                                /* Status: */ response.StatusCode,
                                /* Headers: */ response.Headers.ToString(),
                                /* Body: */ await response.Content.ReadAsStringAsync());

                return null;
            }

            return JObject.Parse(await response.Content.ReadAsStringAsync());
        }

        protected virtual Task<bool> ValidateAudienceAsync(JObject payload) {
            // If no explicit audience has been configured,
            // skip the default audience validation.
            if (Options.Audiences.Count == 0) {
                return Task.FromResult(true);
            }

            // If no "aud" claim was returned by the authorization server,
            // assume the access token was not specific enough and reject it.
            if (payload[OAuthIntrospectionConstants.Claims.Audience] == null) {
                return Task.FromResult(false);
            }

            // Note: the "aud" claim can be either a string or an array.
            // See https://tools.ietf.org/html/rfc7662#section-2.2
            switch (payload[OAuthIntrospectionConstants.Claims.Audience].Type) {
                case JTokenType.Array: {
                    // When the "aud" claim is an array, at least one value must correspond
                    // to the audience registered in the introspection middleware options.
                    var audiences = payload.Value<JArray>(OAuthIntrospectionConstants.Claims.Audience)
                                           .Select(audience => audience.Value<string>());
                    if (audiences.Intersect(Options.Audiences, StringComparer.Ordinal).Any()) {
                        return Task.FromResult(true);
                    }

                    return Task.FromResult(false);
                }

                case JTokenType.String: {
                    // When the "aud" claim is a string, it must exactly match the
                    // audience registered in the introspection middleware options.
                    var audience = payload.Value<string>(OAuthIntrospectionConstants.Claims.Audience);
                    if (Options.Audiences.Contains(audience, StringComparer.Ordinal)) {
                        return Task.FromResult(true);
                    }

                    return Task.FromResult(false);
                }

                default:
                    return Task.FromResult(false);
            }
        }

        protected virtual Task<AuthenticationTicket> CreateTicketAsync(JObject payload) {
            var identity = new ClaimsIdentity(Options.AuthenticationScheme);
            var properties = new AuthenticationProperties();

            foreach (var property in payload.Properties()) {
                switch (property.Name) {
                    // Ignore the unwanted claims.
                    case OAuthIntrospectionConstants.Claims.Active:
                    case OAuthIntrospectionConstants.Claims.TokenType:
                    case OAuthIntrospectionConstants.Claims.NotBefore:
                        continue;

                    case OAuthIntrospectionConstants.Claims.IssuedAt: {
#if DNXCORE50
                        // Convert the UNIX timestamp to a DateTimeOffset.
                        properties.IssuedUtc = DateTimeOffset.FromUnixTimeSeconds((long) property.Value);
#else
                        properties.IssuedUtc = new DateTimeOffset(1970, 1, 1, 0, 0, 0, 0, TimeSpan.Zero) +
                                               TimeSpan.FromSeconds((long) property.Value);
#endif

                        continue;
                    }


                    case OAuthIntrospectionConstants.Claims.ExpiresAt: {
#if DNXCORE50
                        // Convert the UNIX timestamp to a DateTimeOffset.
                        properties.ExpiresUtc = DateTimeOffset.FromUnixTimeSeconds((long) property.Value);
#else
                        properties.ExpiresUtc = new DateTimeOffset(1970, 1, 1, 0, 0, 0, 0, TimeSpan.Zero) +
                                                TimeSpan.FromSeconds((long) property.Value);
#endif

                        continue;
                    }

                    // Add the subject identifier as a new ClaimTypes.NameIdentifier claim.
                    case OAuthIntrospectionConstants.Claims.Subject: {
                        identity.AddClaim(new Claim(ClaimTypes.NameIdentifier, (string) property.Value));

                        continue;
                    }

                    // Add the subject identifier as a new ClaimTypes.Name claim.
                    case OAuthIntrospectionConstants.Claims.Username: {
                        identity.AddClaim(new Claim(ClaimTypes.Name, (string) property.Value));

                        continue;
                    }

                    // Extract the scope values from the space-delimited
                    // "scope" claim and store them as individual claims.
                    // See https://tools.ietf.org/html/rfc7662#section-2.2
                    case OAuthIntrospectionConstants.Claims.Scope: {
                        foreach (var scope in property.Value.ToObject<string>().Split(' ')) {
                            identity.AddClaim(new Claim(property.Name, scope));
                        }

                        continue;
                    }
                }

                switch (property.Value.Type) {
                    // Ignore null values.
                    case JTokenType.None:
                    case JTokenType.Null:
                        continue;

                    case JTokenType.Array: {
                        foreach (var item in (JArray) property.Value) {
                            identity.AddClaim(new Claim(property.Name, (string) item));
                        }

                        continue;
                    }

                    case JTokenType.String: {
                        identity.AddClaim(new Claim(property.Name, (string) property.Value));

                        continue;
                    }

                    case JTokenType.Integer: {
                        identity.AddClaim(new Claim(property.Name, (string) property.Value, ClaimValueTypes.Integer));

                        continue;
                    }
                }
            }

            // Create a new authentication ticket containing the identity
            // built from the claims returned by the authorization server.
            return Task.FromResult(new AuthenticationTicket(
                new ClaimsPrincipal(identity), properties,
                Options.AuthenticationScheme));
        }

        protected virtual Task StoreTicketAsync(string token, AuthenticationTicket ticket) {
            var bytes = Options.TicketSerializer.Serialize(ticket);
            Debug.Assert(bytes != null);

            return Options.Cache.SetAsync(token, bytes, new DistributedCacheEntryOptions {
                AbsoluteExpiration = Options.SystemClock.UtcNow + TimeSpan.FromMinutes(15)
            });
        }

        protected virtual async Task<AuthenticationTicket> RetrieveTicketAsync(string token) {
            // Retrieve the serialized ticket from the distributed cache.
            // If no corresponding entry can be found, null is returned.
            var bytes = await Options.Cache.GetAsync(token);
            if (bytes == null) {
                return null;
            }

            return Options.TicketSerializer.Deserialize(bytes);
        }
    }
}
