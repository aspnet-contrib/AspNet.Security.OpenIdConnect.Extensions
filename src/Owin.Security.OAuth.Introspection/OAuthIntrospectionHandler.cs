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
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Logging;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Infrastructure;
using Newtonsoft.Json.Linq;

namespace Owin.Security.OAuth.Introspection {
    public class OAuthIntrospectionHandler : AuthenticationHandler<OAuthIntrospectionOptions> {
        protected override async Task<AuthenticationTicket> AuthenticateCoreAsync()
        {// Give the application an opportunity to parse the token from a different location, adjust, or reject token
            var parseAccessTokenContext = new ParseAccessTokenContext(Context, Options);
            await Options.Events.ParseAccessToken(parseAccessTokenContext);

            // Initialize the token from the event in case it was set during the event.
            string token = parseAccessTokenContext.Token;

            // Bypass the default processing if the event handled the request parsing.
            if (!parseAccessTokenContext.Handled)
            {
                string header = Request.Headers[OAuthIntrospectionConstants.HeaderNames.Authorization];
                if (string.IsNullOrWhiteSpace(header))
                {
                    Options.Logger.LogError("Authentication failed because the bearer token " +
                                                   "was missing from the 'Authorization' header.");

                    return null;
                }

                // Ensure that the authorization header contains the mandatory "Bearer" scheme.
                // See https://tools.ietf.org/html/rfc6750#section-2.1
                if (!header.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
                {
                    Options.Logger.LogError("Authentication failed because an invalid scheme " +
                                                   "was used in the 'Authorization' header.");

                    return null;
                }

                token = header.Substring("Bearer ".Length);
            }

            if (string.IsNullOrWhiteSpace(token))
            {
                Options.Logger.LogError("Authentication failed because the bearer token " +
                                                "was missing from the request. The default location" +
                                                "is in the 'Authorization' header.");

                return null;
            }

            // Try to resolve the authentication ticket from the distributed cache. If none
            // can be found, a new introspection request is sent to the authorization server.
            var ticket = await RetrieveTicketAsync(token);
            if (ticket == null)
            {
                // Allow interception of the introspection retrieval process via events
                var requestTokenIntrospectionContext = new RequestTokenIntrospectionContext(Context, Options, token);
                await Options.Events.RequestTokenIntrospection(requestTokenIntrospectionContext);

                // Flow the payload from the application possibly handling the introspection request
                var payload = requestTokenIntrospectionContext.Payload;

                if (!requestTokenIntrospectionContext.Handled)
                {
                    // Set the payload using the default introspection behavior
                    payload = await GetIntrospectionPayloadAsync(token);
                }

                // Return a failed authentication result if the introspection
                // request failed or if the "active" claim was false.
                if (payload == null || !payload.Value<bool>(OAuthIntrospectionConstants.Claims.Active))
                {
                    Options.Logger.LogError("Authentication failed because the authorization " +
                                            "server rejected the access token.");

                    return null;
                }

                // Allow interception of the ticket creation process via events
                var createTicketContext = new CreateTicketContext(Context, Options, payload);
                await Options.Events.CreateTicket(createTicketContext);

                // Create a new authentication ticket from the introspection
                // response returned by the authorization server if the application
                // has not handled the ticket creation process.
                ticket = createTicketContext.Handled ? createTicketContext.Ticket : await CreateTicketAsync(payload);
                Debug.Assert(ticket != null);

                await StoreTicketAsync(token, ticket);
            }

            // Allow for interception and handling of the token validated event.
            var validateTokenContext = new ValidateTokenContext(Context, Options, ticket);
            await Options.Events.ValidateToken(validateTokenContext);

            if (validateTokenContext.Handled)
            {
                // Return a result based on how the validation was handled.
                if (validateTokenContext.IsValid)
                {
                    return validateTokenContext.Ticket;
                }

                Options.Logger.LogError("Authentication failed because the access token was not valid.");
                return null;
            }

            // Flow any changes that were made to the ticket during the validation event.
            ticket = validateTokenContext.Ticket;

            // Ensure that the access token was issued
            // to be used with this resource server.
            if (!await ValidateAudienceAsync(ticket))
            {
                Options.Logger.LogError("Authentication failed because the access token " +
                                               "was not valid for this resource server.");

                return null;
            }

            // Ensure that the authentication ticket is still valid.
            if (ticket.Properties.ExpiresUtc.HasValue &&
                ticket.Properties.ExpiresUtc.Value < Options.SystemClock.UtcNow)
            {
                Options.Logger.LogError("Authentication failed because the access token was expired.");

                return null;
            }

            return ticket;
        }

        protected virtual async Task<string> ResolveIntrospectionEndpointAsync(string issuer) {
            if (issuer.EndsWith("/")) {
                issuer = issuer.Substring(0, issuer.Length - 1);
            }

            // Create a new discovery request containing the access token and the client credentials.
            var request = new HttpRequestMessage(HttpMethod.Get, issuer + "/.well-known/openid-configuration");
            request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));

            var response = await Options.HttpClient.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, Request.CallCancelled);
            if (!response.IsSuccessStatusCode) {
                Options.Logger.LogError("An error occurred when retrieving the issuer metadata: the remote server " +
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
            if (string.IsNullOrWhiteSpace(Options.IntrospectionEndpoint)) {
                Options.IntrospectionEndpoint = await ResolveIntrospectionEndpointAsync(Options.Authority);
            }

            if (string.IsNullOrWhiteSpace(Options.IntrospectionEndpoint)) {
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

            var response = await Options.HttpClient.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, Request.CallCancelled);
            if (!response.IsSuccessStatusCode) {
                Options.Logger.LogError("An error occurred when validating an access token: the remote server " +
                                        "returned a {Status} response with the following payload: {Headers} {Body}.",
                                        /* Status: */ response.StatusCode,
                                        /* Headers: */ response.Headers.ToString(),
                                        /* Body: */ await response.Content.ReadAsStringAsync());

                return null;
            }

            return JObject.Parse(await response.Content.ReadAsStringAsync());
        }

        protected virtual Task<bool> ValidateAudienceAsync(AuthenticationTicket ticket)
        {
            // If no explicit audience has been configured,
            // skip the default audience validation.
            if (Options.Audiences.Count == 0)
            {
                return Task.FromResult(true);
            }

            // Extract the audiences from the authentication ticket.
            string audiences;
            if (!ticket.Properties.Dictionary.TryGetValue(OAuthIntrospectionConstants.Properties.Audiences, out audiences))
            {
                return Task.FromResult(false);
            }

            // Ensure that the authentication ticket contains the registered audience.
            if (!audiences.Split(' ').Intersect(Options.Audiences, StringComparer.Ordinal).Any())
            {
                return Task.FromResult(false);
            }

            return Task.FromResult(true);
        }

        protected virtual Task<AuthenticationTicket> CreateTicketAsync(JObject payload) {
            var identity = new ClaimsIdentity(Options.AuthenticationType);
            var properties = new AuthenticationProperties();

            foreach (var property in payload.Properties()) {
                switch (property.Name) {
                    // Ignore the unwanted claims.
                    case OAuthIntrospectionConstants.Claims.Active:
                    case OAuthIntrospectionConstants.Claims.TokenType:
                    case OAuthIntrospectionConstants.Claims.NotBefore:
                        continue;

                    case OAuthIntrospectionConstants.Claims.IssuedAt: {
                        properties.IssuedUtc = new DateTimeOffset(1970, 1, 1, 0, 0, 0, 0, TimeSpan.Zero) +
                                               TimeSpan.FromSeconds((long) property.Value);
                        continue;
                    }


                    case OAuthIntrospectionConstants.Claims.ExpiresAt: {
                        properties.ExpiresUtc = new DateTimeOffset(1970, 1, 1, 0, 0, 0, 0, TimeSpan.Zero) +
                                                TimeSpan.FromSeconds((long) property.Value);

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

                    // Store the audience or audiences in the ticket properties.
                    case OAuthIntrospectionConstants.Claims.Audience: {
                        if (property.Value.Type == JTokenType.Array) {
                            var array = (JArray)property.Value;
                            if (array == null) {
                                continue;
                            }
                            var audiences = string.Join(" ", array.Select(item => item.Value<string>()));
                            properties.Dictionary[OAuthIntrospectionConstants.Properties.Audiences] = audiences;
                        }

                        else if (property.Value.Type == JTokenType.String) {
                            properties.Dictionary[OAuthIntrospectionConstants.Properties.Audiences] = (string)property.Value;
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
            return Task.FromResult(new AuthenticationTicket(identity, properties));
        }

        protected virtual Task StoreTicketAsync(string token, AuthenticationTicket ticket) {
            var bytes = Encoding.UTF8.GetBytes(Options.AccessTokenFormat.Protect(ticket));
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

            return Options.AccessTokenFormat.Unprotect(Encoding.UTF8.GetString(bytes));
        }
    }
}
