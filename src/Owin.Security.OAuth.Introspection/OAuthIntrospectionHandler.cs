/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/aspnet-contrib/AspNet.Security.OAuth.Extensions for more information
 * concerning the license and the contributors participating to this project.
 */

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Infrastructure;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace Owin.Security.OAuth.Introspection
{
    /// <summary>
    /// Provides the logic necessary to extract and validate tokens from HTTP requests.
    /// </summary>
    public class OAuthIntrospectionHandler : AuthenticationHandler<OAuthIntrospectionOptions>
    {
        protected override async Task<AuthenticationTicket> AuthenticateCoreAsync()
        {
            var context = new RetrieveTokenContext(Context, Options);
            await Options.Events.RetrieveToken(context);

            if (context.Handled)
            {
                Logger.LogInformation("The default authentication handling was skipped from user code.");

                return context.Ticket;
            }

            var token = context.Token;

            if (string.IsNullOrEmpty(token))
            {
                // Try to retrieve the access token from the authorization header.
                var header = Request.Headers[OAuthIntrospectionConstants.Headers.Authorization];
                if (string.IsNullOrEmpty(header))
                {
                    Logger.LogDebug("Authentication was skipped because no bearer token was received.");

                    return null;
                }

                // Ensure that the authorization header contains the mandatory "Bearer" scheme.
                // See https://tools.ietf.org/html/rfc6750#section-2.1
                if (!header.StartsWith(OAuthIntrospectionConstants.Schemes.Bearer + ' ', StringComparison.OrdinalIgnoreCase))
                {
                    Logger.LogDebug("Authentication was skipped because an incompatible " +
                                    "scheme was used in the 'Authorization' header.");

                    return null;
                }

                // Extract the token from the authorization header.
                token = header.Substring(OAuthIntrospectionConstants.Schemes.Bearer.Length + 1).Trim();

                if (string.IsNullOrEmpty(token))
                {
                    Logger.LogDebug("Authentication was skipped because the bearer token " +
                                    "was missing from the 'Authorization' header.");

                    return null;
                }
            }

            // Try to resolve the authentication ticket from the distributed cache. If none
            // can be found, a new introspection request is sent to the authorization server.
            var ticket = await RetrieveTicketAsync(token);
            if (ticket == null)
            {
                // Return a failed authentication result if the introspection
                // request failed or if the "active" claim was false.
                var payload = await GetIntrospectionPayloadAsync(token);
                if (payload == null || !payload.Value<bool>(OAuthIntrospectionConstants.Claims.Active))
                {
                    Logger.LogError("Authentication failed because the authorization " +
                                    "server rejected the access token.");

                    Context.Set(typeof(OAuthIntrospectionError).FullName, new OAuthIntrospectionError
                    {
                        Error = OAuthIntrospectionConstants.Errors.InvalidToken,
                        ErrorDescription = "The access token is not valid."
                    });

                    return null;
                }

                // Create a new authentication ticket from the introspection
                // response returned by the authorization server.
                ticket = await CreateTicketAsync(token, payload);
                Debug.Assert(ticket != null);

                await StoreTicketAsync(token, ticket);
            }

            // Ensure that the token can be used as an access token.
            if (!ValidateTokenUsage(ticket))
            {
                Logger.LogError("Authentication failed because the token was not an access token.");

                Context.Set(typeof(OAuthIntrospectionError).FullName, new OAuthIntrospectionError
                {
                    Error = OAuthIntrospectionConstants.Errors.InvalidToken,
                    ErrorDescription = "The access token is not valid."
                });

                return null;
            }

            // Ensure that the authentication ticket is still valid.
            if (ticket.Properties.ExpiresUtc.HasValue &&
                ticket.Properties.ExpiresUtc.Value < Options.SystemClock.UtcNow)
            {
                Logger.LogError("Authentication failed because the access token was expired.");

                Context.Set(typeof(OAuthIntrospectionError).FullName, new OAuthIntrospectionError
                {
                    Error = OAuthIntrospectionConstants.Errors.InvalidToken,
                    ErrorDescription = "The access token is no longer valid."
                });

                return null;
            }

            // Ensure that the access token was issued
            // to be used with this resource server.
            if (!ValidateAudience(ticket))
            {
                Logger.LogError("Authentication failed because the access token " +
                                "was not valid for this resource server.");

                Context.Set(typeof(OAuthIntrospectionError).FullName, new OAuthIntrospectionError
                {
                    Error = OAuthIntrospectionConstants.Errors.InvalidToken,
                    ErrorDescription = "The access token is not valid for this resource server."
                });

                return null;
            }

            var notification = new ValidateTokenContext(Context, Options, ticket);
            await Options.Events.ValidateToken(notification);

            // Allow the application code to replace the ticket
            // reference from the ValidateToken event.
            return notification.Ticket;
        }

        protected override async Task ApplyResponseChallengeAsync()
        {
            var context = Helper.LookupChallenge(Options.AuthenticationType, Options.AuthenticationMode);
            if (context == null || Response.StatusCode != 401)
            {
                return;
            }

            Response.StatusCode = 200;

            // Note: always return the error/error_description/error_uri/realm/scope specified
            // in the authentication properties even if IncludeErrorDetails is set to false.
            var notification = new ApplyChallengeContext(Context, Options, context.Properties)
            {
                Error = context.Properties.GetProperty(OAuthIntrospectionConstants.Properties.Error),
                ErrorDescription = context.Properties.GetProperty(OAuthIntrospectionConstants.Properties.ErrorDescription),
                ErrorUri = context.Properties.GetProperty(OAuthIntrospectionConstants.Properties.ErrorUri),
                Realm = context.Properties.GetProperty(OAuthIntrospectionConstants.Properties.Realm),
                Scope = context.Properties.GetProperty(OAuthIntrospectionConstants.Properties.Scope),
            };

            // If an error was stored by HandleAuthenticateAsync,
            // add the corresponding details to the notification.
            var error = Context.Get<OAuthIntrospectionError>(typeof(OAuthIntrospectionError).FullName);
            if (error != null && Options.IncludeErrorDetails)
            {
                // If no error was specified in the authentication properties,
                // try to use the error returned from HandleAuthenticateAsync.
                if (string.IsNullOrEmpty(notification.Error))
                {
                    notification.Error = error.Error;
                }

                // If no error_description was specified in the authentication properties,
                // try to use the error_description returned from AuthenticateCoreAsync.
                if (string.IsNullOrEmpty(notification.ErrorDescription))
                {
                    notification.ErrorDescription = error.ErrorDescription;
                }

                // If no error_uri was specified in the authentication properties,
                // try to use the error_uri returned from AuthenticateCoreAsync.
                if (string.IsNullOrEmpty(notification.ErrorUri))
                {
                    notification.ErrorUri = error.ErrorUri;
                }

                // If no realm was specified in the authentication properties,
                // try to use the realm returned from AuthenticateCoreAsync.
                if (string.IsNullOrEmpty(notification.Realm))
                {
                    notification.Realm = error.Realm;
                }

                // If no scope was specified in the authentication properties,
                // try to use the scope returned from AuthenticateCoreAsync.
                if (string.IsNullOrEmpty(notification.Scope))
                {
                    notification.Scope = error.Scope;
                }
            }

            // At this stage, if no realm was provided, try to
            // fallback to the realm registered in the options.
            if (string.IsNullOrEmpty(notification.Realm))
            {
                notification.Realm = Options.Realm;
            }

            await Options.Events.ApplyChallenge(notification);

            if (notification.Handled)
            {
                return;
            }

            Response.StatusCode = 401;

            // Optimization: avoid allocating a StringBuilder if the
            // WWW-Authenticate header doesn't contain any parameter.
            if (string.IsNullOrEmpty(notification.Realm) &&
                string.IsNullOrEmpty(notification.Error) &&
                string.IsNullOrEmpty(notification.ErrorDescription) &&
                string.IsNullOrEmpty(notification.ErrorUri) &&
                string.IsNullOrEmpty(notification.Scope))
            {
                Response.Headers.Append(OAuthIntrospectionConstants.Headers.WWWAuthenticate,
                                        OAuthIntrospectionConstants.Schemes.Bearer);
            }

            else
            {
                var builder = new StringBuilder(OAuthIntrospectionConstants.Schemes.Bearer);

                // Append the realm if one was specified.
                if (!string.IsNullOrEmpty(notification.Realm))
                {
                    builder.Append(' ');
                    builder.Append(OAuthIntrospectionConstants.Parameters.Realm);
                    builder.Append("=\"");
                    builder.Append(notification.Realm);
                    builder.Append('"');
                }

                // Append the error if one was specified.
                if (!string.IsNullOrEmpty(notification.Error))
                {
                    if (!string.IsNullOrEmpty(notification.Realm))
                    {
                        builder.Append(',');
                    }

                    builder.Append(' ');
                    builder.Append(OAuthIntrospectionConstants.Parameters.Error);
                    builder.Append("=\"");
                    builder.Append(notification.Error);
                    builder.Append('"');
                }

                // Append the error_description if one was specified.
                if (!string.IsNullOrEmpty(notification.ErrorDescription))
                {
                    if (!string.IsNullOrEmpty(notification.Realm) ||
                        !string.IsNullOrEmpty(notification.Error))
                    {
                        builder.Append(',');
                    }

                    builder.Append(' ');
                    builder.Append(OAuthIntrospectionConstants.Parameters.ErrorDescription);
                    builder.Append("=\"");
                    builder.Append(notification.ErrorDescription);
                    builder.Append('"');
                }

                // Append the error_uri if one was specified.
                if (!string.IsNullOrEmpty(notification.ErrorUri))
                {
                    if (!string.IsNullOrEmpty(notification.Realm) ||
                        !string.IsNullOrEmpty(notification.Error) ||
                        !string.IsNullOrEmpty(notification.ErrorDescription))
                    {
                        builder.Append(',');
                    }

                    builder.Append(' ');
                    builder.Append(OAuthIntrospectionConstants.Parameters.ErrorUri);
                    builder.Append("=\"");
                    builder.Append(notification.ErrorUri);
                    builder.Append('"');
                }

                // Append the scope if one was specified.
                if (!string.IsNullOrEmpty(notification.Scope))
                {
                    if (!string.IsNullOrEmpty(notification.Realm) ||
                        !string.IsNullOrEmpty(notification.Error) ||
                        !string.IsNullOrEmpty(notification.ErrorDescription) ||
                        !string.IsNullOrEmpty(notification.ErrorUri))
                    {
                        builder.Append(',');
                    }

                    builder.Append(' ');
                    builder.Append(OAuthIntrospectionConstants.Parameters.Scope);
                    builder.Append("=\"");
                    builder.Append(notification.Scope);
                    builder.Append('"');
                }

                Response.Headers.Append(OAuthIntrospectionConstants.Headers.WWWAuthenticate, builder.ToString());
            }
        }

        private async Task<JObject> GetIntrospectionPayloadAsync(string token)
        {
            var configuration = await Options.ConfigurationManager.GetConfigurationAsync(default);
            if (configuration == null)
            {
                throw new InvalidOperationException("The OAuth2 introspection middleware was unable to retrieve " +
                                                    "the provider configuration from the authorization server.");
            }

            if (string.IsNullOrEmpty(configuration.IntrospectionEndpoint))
            {
                throw new InvalidOperationException("The OAuth2 introspection middleware was unable to retrieve " +
                                                    "the introspection endpoint address from the discovery document.");
            }

            // Create a new introspection request containing the access token and the client credentials.
            var request = new HttpRequestMessage(HttpMethod.Post, configuration.IntrospectionEndpoint);
            request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));

            // Note: always specify the token_type_hint to help
            // the authorization server make a faster token lookup.
            var parameters = new Dictionary<string, string>
            {
                [OAuthIntrospectionConstants.Parameters.Token] = token,
                [OAuthIntrospectionConstants.Parameters.TokenTypeHint] = OAuthIntrospectionConstants.TokenTypeHints.AccessToken
            };

            // If the introspection endpoint provided by the authorization server supports
            // client_secret_post, flow the client credentials as regular OAuth2 parameters.
            // See https://tools.ietf.org/html/draft-ietf-oauth-discovery-05#section-2
            // and https://tools.ietf.org/html/rfc6749#section-2.3.1 for more information.
            if (configuration.IntrospectionEndpointAuthMethodsSupported.Contains(OAuthIntrospectionConstants.ClientAuthenticationMethods.ClientSecretPost))
            {
                parameters[OAuthIntrospectionConstants.Parameters.ClientId] = Options.ClientId;
                parameters[OAuthIntrospectionConstants.Parameters.ClientSecret] = Options.ClientSecret;
            }

            // Otherwise, assume the authorization server only supports basic authentication,
            // as it's the only authentication method required by the OAuth2 specification.
            // See https://tools.ietf.org/html/rfc6749#section-2.3.1 for more information.
            else
            {
                string EscapeDataString(string value)
                {
                    if (string.IsNullOrEmpty(value))
                    {
                        return null;
                    }

                    return Uri.EscapeDataString(value).Replace("%20", "+");
                }

                var credentials = Convert.ToBase64String(Encoding.ASCII.GetBytes(
                    string.Concat(
                        EscapeDataString(Options.ClientId), ":",
                        EscapeDataString(Options.ClientSecret))));

                request.Headers.Authorization = new AuthenticationHeaderValue(OAuthIntrospectionConstants.Schemes.Basic, credentials);
            }

            request.Content = new FormUrlEncodedContent(parameters);

            var notification = new SendIntrospectionRequestContext(Context, Options, request, token);
            await Options.Events.SendIntrospectionRequest(notification);

            if (notification.Handled)
            {
                Logger.LogInformation("The default challenge handling was skipped from user code.");

                return null;
            }

            var response = notification.Response;
            if (response == null)
            {
                response = await Options.HttpClient.SendAsync(request);
            }

            if (!response.IsSuccessStatusCode)
            {
                Logger.LogError("An error occurred while validating an access token: the remote server " +
                                "returned a {Status} response with the following payload: {Headers} {Body}.",
                                /* Status: */ response.StatusCode,
                                /* Headers: */ response.Headers.ToString(),
                                /* Body: */ await response.Content.ReadAsStringAsync());

                return null;
            }

            using (var stream = await response.Content.ReadAsStreamAsync())
            using (var reader = new JsonTextReader(new StreamReader(stream)))
            {
                // Limit the maximum depth to prevent stack overflow exceptions from
                // being thrown when receiving deeply nested introspection responses.
                reader.MaxDepth = 20;

                try
                {
                    var payload = JObject.Load(reader);

                    Logger.LogInformation("The introspection response was successfully extracted: {Response}.", payload);

                    return payload;
                }

                // Swallow the known exceptions thrown by JSON.NET.
                catch (Exception exception) when (exception is ArgumentException ||
                                                  exception is FormatException ||
                                                  exception is InvalidCastException ||
                                                  exception is JsonReaderException ||
                                                  exception is JsonSerializationException)
                {
                    Logger.LogError(exception, "An error occurred while deserializing the introspection response.");

                    return null;
                }
            }
        }

        private bool ValidateTokenUsage(AuthenticationTicket ticket)
        {
            // Try to extract the "token_usage" resolved from the introspection response.
            // If this non-standard claim was not returned by the authorization server,
            // assume the validated token can be used as an access token.
            var usage = ticket.Properties.GetProperty(OAuthIntrospectionConstants.Properties.TokenUsage);
            if (string.IsNullOrEmpty(usage))
            {
                return true;
            }

            // If the "token_usage" claim was returned, it must be equal to "access_token".
            return string.Equals(usage, OAuthIntrospectionConstants.TokenUsages.AccessToken, StringComparison.OrdinalIgnoreCase);
        }

        private bool ValidateAudience(AuthenticationTicket ticket)
        {
            // If no explicit audience has been configured,
            // skip the default audience validation.
            if (Options.Audiences.Count == 0)
            {
                return true;
            }

            // Extract the audiences from the authentication ticket.
            var audiences = ticket.Properties.GetProperty(OAuthIntrospectionConstants.Properties.Audiences);
            if (string.IsNullOrEmpty(audiences))
            {
                return false;
            }

            // Ensure that the authentication ticket contains one of the registered audiences.
            foreach (var audience in JArray.Parse(audiences).Values<string>())
            {
                if (Options.Audiences.Contains(audience))
                {
                    return true;
                }
            }

            return false;
        }

        private async Task<AuthenticationTicket> CreateTicketAsync(string token, JObject payload)
        {
            var identity = new ClaimsIdentity(Options.AuthenticationType, Options.NameClaimType, Options.RoleClaimType);
            var properties = new AuthenticationProperties();

            if (Options.SaveToken)
            {
                // Store the access token in the authentication ticket.
                properties.Dictionary[OAuthIntrospectionConstants.Properties.AccessToken] = token;
            }

            foreach (var property in payload.Properties())
            {
                // Always exclude null values, as they can't be represented as valid claims.
                if (property.Value.Type == JTokenType.None || property.Value.Type == JTokenType.Null)
                {
                    Logger.LogInformation("The '{Claim}' claim was excluded because it was null.", property.Name);

                    continue;
                }

                // When the claim correspond to a protocol claim, store it as an
                // authentication property instead of adding it as a proper claim.
                switch (property.Name)
                {
                    // Always exclude the unwanted protocol claims.
                    case OAuthIntrospectionConstants.Claims.Active:
                    case OAuthIntrospectionConstants.Claims.TokenType:
                    case OAuthIntrospectionConstants.Claims.NotBefore:
                        continue;

                    case OAuthIntrospectionConstants.Claims.TokenUsage:
                    {
                        if (property.Value.Type != JTokenType.String)
                        {
                            Logger.LogWarning("The 'token_usage' claim was ignored because it was not a string value.");

                            continue;
                        }

                        properties.Dictionary[OAuthIntrospectionConstants.Properties.TokenUsage] = (string) property.Value;

                        continue;
                    }

                    case OAuthIntrospectionConstants.Claims.IssuedAt:
                    {
                        // Note: the iat claim must be a numeric date value.
                        // See https://tools.ietf.org/html/rfc7662#section-2.2
                        // and https://tools.ietf.org/html/rfc7519#section-4.1.6 for more information.
                        if (property.Value.Type != JTokenType.Float && property.Value.Type != JTokenType.Integer)
                        {
                            Logger.LogWarning("The 'iat' claim was ignored because it was not a decimal value.");

                            continue;
                        }

                        properties.IssuedUtc = new DateTimeOffset(1970, 1, 1, 0, 0, 0, 0, TimeSpan.Zero) +
                                               TimeSpan.FromSeconds((double) property.Value);

                        continue;
                    }

                    case OAuthIntrospectionConstants.Claims.ExpiresAt:
                    {
                        // Note: the exp claim must be a numeric date value.
                        // See https://tools.ietf.org/html/rfc7662#section-2.2
                        // and https://tools.ietf.org/html/rfc7519#section-4.1.4 for more information.
                        if (property.Value.Type != JTokenType.Float && property.Value.Type != JTokenType.Integer)
                        {
                            Logger.LogWarning("The 'exp' claim was ignored because it was not a decimal value.");

                            continue;
                        }

                        properties.ExpiresUtc = new DateTimeOffset(1970, 1, 1, 0, 0, 0, 0, TimeSpan.Zero) +
                                                TimeSpan.FromSeconds((double) property.Value);

                        continue;
                    }

                    case OAuthIntrospectionConstants.Claims.JwtId:
                    {
                        // Note: the jti claim must be a string value.
                        // See https://tools.ietf.org/html/rfc7662#section-2.2
                        // and https://tools.ietf.org/html/rfc7519#section-4.1.7 for more information.
                        if (property.Value.Type != JTokenType.String)
                        {
                            Logger.LogWarning("The 'jti' claim was ignored because it was not a string value.");

                            continue;
                        }

                        properties.Dictionary[OAuthIntrospectionConstants.Properties.TokenId] = (string) property;

                        continue;
                    }

                    case OAuthIntrospectionConstants.Claims.Scope:
                    {
                        // Note: the scope claim must be a space-separated string value.
                        // See https://tools.ietf.org/html/rfc7662#section-2.2
                        // and https://tools.ietf.org/html/rfc7519#section-4.1.7 for more information.
                        if (property.Value.Type != JTokenType.String)
                        {
                            Logger.LogWarning("The 'scope' claim was ignored because it was not a string value.");

                            continue;
                        }

                        var scopes = ((string) property.Value).Split(
                            OAuthIntrospectionConstants.Separators.Space,
                            StringSplitOptions.RemoveEmptyEntries);

                        // Note: the OpenID Connect extensions require storing the scopes
                        // as an array of strings, even if there's only element in the array.
                        properties.Dictionary[OAuthIntrospectionConstants.Properties.Scopes] =
                            new JArray(scopes).ToString(Formatting.None);

                        // For convenience, also store the scopes as individual claims.
                        foreach (var scope in scopes)
                        {
                            identity.AddClaim(new Claim(property.Name, scope));
                        }

                        continue;
                    }

                    case OAuthIntrospectionConstants.Claims.Audience:
                    {
                        // Note: the aud claim must be either a string value or an array of strings.
                        // See https://tools.ietf.org/html/rfc7662#section-2.2
                        // and https://tools.ietf.org/html/rfc7519#section-4.1.4 for more information.
                        if (property.Value.Type == JTokenType.String)
                        {
                            // Note: the OpenID Connect extensions require storing the audiences
                            // as an array of strings, even if there's only element in the array.
                            properties.Dictionary[OAuthIntrospectionConstants.Properties.Audiences] =
                                new JArray((string) property.Value).ToString(Formatting.None);

                            continue;
                        }

                        else if (property.Value.Type == JTokenType.Array)
                        {
                            // Ensure all the array values are valid strings.
                            var audiences = (JArray) property.Value;
                            if (audiences.Any(audience => audience.Type != JTokenType.String))
                            {
                                Logger.LogWarning("The 'aud' claim was ignored because it was not an array of strings.");

                                continue;
                            }

                            properties.Dictionary[OAuthIntrospectionConstants.Properties.Audiences] =
                                property.Value.ToString(Formatting.None);

                            continue;
                        }

                        Logger.LogWarning("The 'aud' claim was ignored because it was not a string nor an array.");

                        continue;
                    }
                }

                // If the claim is not a known claim, add it as-is by
                // trying to determine what's the best claim value type.
                switch (property.Value.Type)
                {
                    case JTokenType.String:
                        identity.AddClaim(new Claim(property.Name, (string) property.Value, ClaimValueTypes.String));
                        continue;

                    case JTokenType.Integer:
                        identity.AddClaim(new Claim(property.Name, (string) property.Value, ClaimValueTypes.Integer));
                        continue;

                    case JTokenType.Float:
                        identity.AddClaim(new Claim(property.Name, (string) property.Value, ClaimValueTypes.Double));
                        continue;

                    case JTokenType.Array:
                    {
                        // When the claim is an array, add the corresponding items
                        // as individual claims using the name assigned to the array.
                        foreach (var value in (JArray) property.Value)
                        {
                            switch (value.Type)
                            {
                                case JTokenType.None:
                                case JTokenType.Null:
                                    continue;

                                case JTokenType.String:
                                    identity.AddClaim(new Claim(property.Name, (string) value, ClaimValueTypes.String));
                                    continue;

                                case JTokenType.Integer:
                                    identity.AddClaim(new Claim(property.Name, (string) value, ClaimValueTypes.Integer));
                                    continue;

                                case JTokenType.Float:
                                    identity.AddClaim(new Claim(property.Name, (string) value, ClaimValueTypes.Double));
                                    continue;

                                case JTokenType.Array:
                                {
                                    // When the array element is itself a new array, serialize it as-it.
                                    identity.AddClaim(new Claim(property.Name, value.ToString(Formatting.None),
                                        OAuthIntrospectionConstants.ClaimValueTypes.JsonArray));

                                    continue;
                                }

                                default:
                                {
                                    // When the array element doesn't correspond to a supported
                                    // primitive type (e.g a complex object), serialize it as-it.
                                    identity.AddClaim(new Claim(property.Name, value.ToString(Formatting.None),
                                        OAuthIntrospectionConstants.ClaimValueTypes.Json));

                                    continue;
                                }
                            }
                        }

                        continue;
                    }

                    default:
                    {
                        // When the array element doesn't correspond to a supported
                        // primitive type (e.g a complex object), serialize it as-it.
                        identity.AddClaim(new Claim(property.Name, property.Value.ToString(Formatting.None),
                            OAuthIntrospectionConstants.ClaimValueTypes.Json));

                        continue;
                    }
                }
            }

            // Create a new authentication ticket containing the identity
            // built from the claims returned by the authorization server.
            var ticket = new AuthenticationTicket(identity, properties);

            var notification = new CreateTicketContext(Context, Options, ticket, payload);
            await Options.Events.CreateTicket(notification);

            return notification.Ticket;
        }

        private Task StoreTicketAsync(string token, AuthenticationTicket ticket)
        {
            if (Options.CachingPolicy == null)
            {
                return Task.FromResult(0);
            }

            var bytes = Encoding.UTF8.GetBytes(Options.AccessTokenFormat.Protect(ticket));
            Debug.Assert(bytes != null);

            return Options.Cache.SetAsync(token, bytes, Options.CachingPolicy);
        }

        private async Task<AuthenticationTicket> RetrieveTicketAsync(string token)
        {
            if (Options.CachingPolicy == null)
            {
                return null;
            }

            // Retrieve the serialized ticket from the distributed cache.
            // If no corresponding entry can be found, null is returned.
            var bytes = await Options.Cache.GetAsync(token);
            if (bytes == null)
            {
                return null;
            }

            return Options.AccessTokenFormat.Unprotect(Encoding.UTF8.GetString(bytes));
        }

        private ILogger Logger => Options.Logger;
    }
}
