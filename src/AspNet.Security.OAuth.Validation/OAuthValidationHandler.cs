﻿/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/aspnet-contrib/AspNet.Security.OAuth.Extensions for more information
 * concerning the license and the contributors participating to this project.
 */

using System;
using System.Security.Claims;
using System.Text;
using System.Text.Encodings.Web;
using System.Threading.Tasks;
using JetBrains.Annotations;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.Net.Http.Headers;
using Newtonsoft.Json.Linq;

namespace AspNet.Security.OAuth.Validation
{
    /// <summary>
    /// Provides the logic necessary to extract and validate tokens from HTTP requests.
    /// </summary>
    public class OAuthValidationHandler : AuthenticationHandler<OAuthValidationOptions>
    {
        public OAuthValidationHandler(
            [NotNull] IOptionsMonitor<OAuthValidationOptions> options,
            [NotNull] ILoggerFactory logger,
            [NotNull] UrlEncoder encoder,
            [NotNull] ISystemClock clock)
            : base(options, logger, encoder, clock)
        {
        }

        protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
        {
            var context = new RetrieveTokenContext(Context, Scheme, Options);
            await Events.RetrieveToken(context);

            if (context.Result != null)
            {
                Logger.LogInformation("The default authentication handling was skipped from user code.");

                return context.Result;
            }

            var token = context.Token;

            if (string.IsNullOrEmpty(token))
            {
                // Try to retrieve the access token from the authorization header.
                string header = Request.Headers[HeaderNames.Authorization];
                if (string.IsNullOrEmpty(header))
                {
                    Logger.LogDebug("Authentication was skipped because no bearer token was received.");

                    return AuthenticateResult.NoResult();
                }

                // Ensure that the authorization header contains the mandatory "Bearer" scheme.
                // See https://tools.ietf.org/html/rfc6750#section-2.1
                if (!header.StartsWith(OAuthValidationConstants.Schemes.Bearer + ' ', StringComparison.OrdinalIgnoreCase))
                {
                    Logger.LogDebug("Authentication was skipped because an incompatible " +
                                    "scheme was used in the 'Authorization' header.");

                    return AuthenticateResult.NoResult();
                }

                // Extract the token from the authorization header.
                token = header.Substring(OAuthValidationConstants.Schemes.Bearer.Length + 1).Trim();

                if (string.IsNullOrEmpty(token))
                {
                    Logger.LogDebug("Authentication was skipped because the bearer token " +
                                    "was missing from the 'Authorization' header.");

                    return AuthenticateResult.NoResult();
                }
            }

            // Try to unprotect the token and return an error
            // if the ticket can't be decrypted or validated.
            var result = await CreateTicketAsync(token);
            if (!result.Succeeded)
            {
                Context.Features.Set(new OAuthValidationFeature
                {
                    Error = new OAuthValidationError
                    {
                        Error = OAuthValidationConstants.Errors.InvalidToken,
                        ErrorDescription = "The access token is not valid."
                    }
                });

                return result;
            }

            // Ensure that the authentication ticket is still valid.
            var ticket = result.Ticket;
            if (ticket.Properties.ExpiresUtc.HasValue &&
                ticket.Properties.ExpiresUtc.Value < Options.SystemClock.UtcNow)
            {
                Context.Features.Set(new OAuthValidationFeature
                {
                    Error = new OAuthValidationError
                    {
                        Error = OAuthValidationConstants.Errors.InvalidToken,
                        ErrorDescription = "The access token is no longer valid."
                    }
                });

                return AuthenticateResult.Fail("Authentication failed because the access token was expired.");
            }

            // Ensure that the access token was issued
            // to be used with this resource server.
            if (!ValidateAudience(ticket))
            {
                Context.Features.Set(new OAuthValidationFeature
                {
                    Error = new OAuthValidationError
                    {
                        Error = OAuthValidationConstants.Errors.InvalidToken,
                        ErrorDescription = "The access token is not valid for this resource server."
                    }
                });

                return AuthenticateResult.Fail("Authentication failed because the access token " +
                                               "was not valid for this resource server.");
            }

            var notification = new ValidateTokenContext(Context, Scheme, Options, ticket);
            await Events.ValidateToken(notification);

            if (notification.Result != null)
            {
                Logger.LogInformation("The default authentication handling was skipped from user code.");

                return notification.Result;
            }

            // Optimization: avoid allocating a new AuthenticationTicket
            // if the principal/properties instances were not replaced.
            if (ReferenceEquals(notification.Principal, ticket.Principal) &&
                ReferenceEquals(notification.Properties, ticket.Properties))
            {
                return AuthenticateResult.Success(ticket);
            }

            return AuthenticateResult.Success(new AuthenticationTicket(
                notification.Principal, notification.Properties, Scheme.Name));
        }

        protected override async Task HandleChallengeAsync(AuthenticationProperties properties)
        {
            // Note: always return the error/error_description/error_uri/realm/scope specified
            // in the authentication properties even if IncludeErrorDetails is set to false.
            var notification = new ApplyChallengeContext(Context, Scheme, Options, properties)
            {
                Error = properties.GetProperty(OAuthValidationConstants.Properties.Error),
                ErrorDescription = properties.GetProperty(OAuthValidationConstants.Properties.ErrorDescription),
                ErrorUri = properties.GetProperty(OAuthValidationConstants.Properties.ErrorUri),
                Realm = properties.GetProperty(OAuthValidationConstants.Properties.Realm),
                Scope = properties.GetProperty(OAuthValidationConstants.Properties.Scope),
            };

            // If an error was stored by HandleAuthenticateAsync,
            // add the corresponding details to the notification.
            var error = Context.Features.Get<OAuthValidationFeature>()?.Error;
            if (error != null && Options.IncludeErrorDetails)
            {
                // If no error was specified in the authentication properties,
                // try to use the error returned from HandleAuthenticateAsync.
                if (string.IsNullOrEmpty(notification.Error))
                {
                    notification.Error = error.Error;
                }

                // If no error_description was specified in the authentication properties,
                // try to use the error_description returned from HandleAuthenticateAsync.
                if (string.IsNullOrEmpty(notification.ErrorDescription))
                {
                    notification.ErrorDescription = error.ErrorDescription;
                }

                // If no error_uri was specified in the authentication properties,
                // try to use the error_uri returned from HandleAuthenticateAsync.
                if (string.IsNullOrEmpty(notification.ErrorUri))
                {
                    notification.ErrorUri = error.ErrorUri;
                }

                // If no realm was specified in the authentication properties,
                // try to use the realm returned from HandleAuthenticateAsync.
                if (string.IsNullOrEmpty(notification.Realm))
                {
                    notification.Realm = error.Realm;
                }

                // If no scope was specified in the authentication properties,
                // try to use the scope returned from HandleAuthenticateAsync.
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

            await Events.ApplyChallenge(notification);

            if (notification.Handled)
            {
                Logger.LogInformation("The default challenge handling was skipped from user code.");

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
                Response.Headers.Append(HeaderNames.WWWAuthenticate, OAuthValidationConstants.Schemes.Bearer);
            }

            else
            {
                var builder = new StringBuilder(OAuthValidationConstants.Schemes.Bearer);

                // Append the realm if one was specified.
                if (!string.IsNullOrEmpty(notification.Realm))
                {
                    builder.Append(' ');
                    builder.Append(OAuthValidationConstants.Parameters.Realm);
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
                    builder.Append(OAuthValidationConstants.Parameters.Error);
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
                    builder.Append(OAuthValidationConstants.Parameters.ErrorDescription);
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
                    builder.Append(OAuthValidationConstants.Parameters.ErrorUri);
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
                    builder.Append(OAuthValidationConstants.Parameters.Scope);
                    builder.Append("=\"");
                    builder.Append(notification.Scope);
                    builder.Append('"');
                }

                Response.Headers.Append(HeaderNames.WWWAuthenticate, builder.ToString());
            }
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
            var audiences = ticket.Properties.GetProperty(OAuthValidationConstants.Properties.Audiences);
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

        private async Task<AuthenticateResult> DecryptTokenAsync(string token)
        {
            var notification = new DecryptTokenContext(Context, Scheme, Options, token)
            {
                DataFormat = Options.AccessTokenFormat
            };

            await Events.DecryptToken(notification);

            if (notification.Result != null)
            {
                Logger.LogInformation("The default authentication handling was skipped from user code.");

                return notification.Result;
            }

            if (notification.DataFormat == null)
            {
                throw new InvalidOperationException("A data formatter must be provided.");
            }

            var ticket = notification.DataFormat.Unprotect(token);
            if (ticket == null)
            {
                return AuthenticateResult.Fail("Authentication failed because the access token was invalid.");
            }

            return AuthenticateResult.Success(ticket);
        }

        private async Task<AuthenticateResult> CreateTicketAsync(string token)
        {
            var result = await DecryptTokenAsync(token);
            if (!result.Succeeded)
            {
                return result;
            }

            var ticket = result.Ticket;
            if (ticket == null)
            {
                return AuthenticateResult.Fail("Authentication failed because the access token was invalid.");
            }

            if (Options.SaveToken)
            {
                // Store the access token in the authentication ticket.
                ticket.Properties.StoreTokens(new[]
                {
                    new AuthenticationToken { Name = OAuthValidationConstants.Properties.Token, Value = token }
                });
            }

            // Resolve the primary identity associated with the principal.
            var identity = (ClaimsIdentity) ticket.Principal.Identity;

            // Copy the scopes extracted from the authentication ticket to the
            // ClaimsIdentity to make them easier to retrieve from application code.
            var scopes = ticket.Properties.GetProperty(OAuthValidationConstants.Properties.Scopes);
            if (!string.IsNullOrEmpty(scopes))
            {
                foreach (var scope in JArray.Parse(scopes).Values<string>())
                {
                    identity.AddClaim(new Claim(OAuthValidationConstants.Claims.Scope, scope));
                }
            }

            var notification = new CreateTicketContext(Context, Scheme, Options, ticket);
            await Events.CreateTicket(notification);

            if (notification.Result != null)
            {
                Logger.LogInformation("The default authentication handling was skipped from user code.");

                return notification.Result;
            }

            // Optimization: avoid allocating a new AuthenticationTicket
            // if the principal/properties instances were not replaced.
            if (ReferenceEquals(notification.Principal, ticket.Principal) &&
                ReferenceEquals(notification.Properties, ticket.Properties))
            {
                return AuthenticateResult.Success(ticket);
            }

            return AuthenticateResult.Success(new AuthenticationTicket(
                notification.Principal, notification.Properties, Scheme.Name));
        }

        private new OAuthValidationEvents Events => (OAuthValidationEvents) base.Events;
    }
}
