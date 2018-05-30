/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/aspnet-contrib/AspNet.Security.OAuth.Extensions for more information
 * concerning the license and the contributors participating to this project.
 */

using System;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Infrastructure;
using Newtonsoft.Json.Linq;

namespace Owin.Security.OAuth.Validation
{
    /// <summary>
    /// Provides the logic necessary to extract and validate tokens from HTTP requests.
    /// </summary>
    public class OAuthValidationHandler : AuthenticationHandler<OAuthValidationOptions>
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
                var header = Request.Headers[OAuthValidationConstants.Headers.Authorization];
                if (string.IsNullOrEmpty(header))
                {
                    Logger.LogDebug("Authentication was skipped because no bearer token was received.");

                    return null;
                }

                // Ensure that the authorization header contains the mandatory "Bearer" scheme.
                // See https://tools.ietf.org/html/rfc6750#section-2.1
                if (!header.StartsWith(OAuthValidationConstants.Schemes.Bearer + ' ', StringComparison.OrdinalIgnoreCase))
                {
                    Logger.LogDebug("Authentication was skipped because an incompatible " +
                                    "scheme was used in the 'Authorization' header.");

                    return null;
                }

                // Extract the token from the authorization header.
                token = header.Substring(OAuthValidationConstants.Schemes.Bearer.Length + 1).Trim();

                if (string.IsNullOrEmpty(token))
                {
                    Logger.LogDebug("Authentication was skipped because the bearer token " +
                                    "was missing from the 'Authorization' header.");

                    return null;
                }
            }

            // Try to unprotect the token and return an error
            // if the ticket can't be decrypted or validated.
            var ticket = await CreateTicketAsync(token);
            if (ticket == null)
            {
                Logger.LogError("Authentication failed because the access token was invalid.");

                Context.Set(typeof(OAuthValidationError).FullName, new OAuthValidationError
                {
                    Error = OAuthValidationConstants.Errors.InvalidToken,
                    ErrorDescription = "The access token is not valid."
                });

                return null;
            }

            // Ensure that the authentication ticket is still valid.
            if (ticket.Properties.ExpiresUtc.HasValue &&
                ticket.Properties.ExpiresUtc.Value < Options.SystemClock.UtcNow)
            {
                Logger.LogError("Authentication failed because the access token was expired.");

                Context.Set(typeof(OAuthValidationError).FullName, new OAuthValidationError
                {
                    Error = OAuthValidationConstants.Errors.InvalidToken,
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

                Context.Set(typeof(OAuthValidationError).FullName, new OAuthValidationError
                {
                    Error = OAuthValidationConstants.Errors.InvalidToken,
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
                Error = context.Properties.GetProperty(OAuthValidationConstants.Properties.Error),
                ErrorDescription = context.Properties.GetProperty(OAuthValidationConstants.Properties.ErrorDescription),
                ErrorUri = context.Properties.GetProperty(OAuthValidationConstants.Properties.ErrorUri),
                Realm = context.Properties.GetProperty(OAuthValidationConstants.Properties.Realm),
                Scope = context.Properties.GetProperty(OAuthValidationConstants.Properties.Scope),
            };

            // If an error was stored by AuthenticateCoreAsync,
            // add the corresponding details to the notification.
            var error = Context.Get<OAuthValidationError>(typeof(OAuthValidationError).FullName);
            if (error != null && Options.IncludeErrorDetails)
            {
                // If no error was specified in the authentication properties,
                // try to use the error returned from AuthenticateCoreAsync.
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
                Response.Headers.Append(OAuthValidationConstants.Headers.WWWAuthenticate,
                                        OAuthValidationConstants.Schemes.Bearer);
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

                Response.Headers.Append(OAuthValidationConstants.Headers.WWWAuthenticate, builder.ToString());
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

        private async Task<AuthenticationTicket> DecryptTokenAsync(string token)
        {
            var notification = new DecryptTokenContext(Context, Options, token)
            {
                DataFormat = Options.AccessTokenFormat
            };

            await Options.Events.DecryptToken(notification);

            if (notification.Handled)
            {
                Logger.LogInformation("The default authentication handling was skipped from user code.");

                return notification.Ticket;
            }

            if (notification.DataFormat == null)
            {
                throw new InvalidOperationException("A data formatter must be provided.");
            }

            return notification.DataFormat.Unprotect(token);
        }

        private async Task<AuthenticationTicket> CreateTicketAsync(string token)
        {
            var ticket = await DecryptTokenAsync(token);
            if (ticket == null)
            {
                return null;
            }

            if (Options.SaveToken)
            {
                // Store the access token in the authentication ticket.
                ticket.Properties.Dictionary[OAuthValidationConstants.Properties.Token] = token;
            }

            // Copy the scopes extracted from the authentication ticket to the
            // ClaimsIdentity to make them easier to retrieve from application code.
            var scopes = ticket.Properties.GetProperty(OAuthValidationConstants.Properties.Scopes);
            if (!string.IsNullOrEmpty(scopes))
            {
                foreach (var scope in JArray.Parse(scopes).Values<string>())
                {
                    ticket.Identity.AddClaim(new Claim(OAuthValidationConstants.Claims.Scope, scope));
                }
            }

            var notification = new CreateTicketContext(Context, Options, ticket);
            await Options.Events.CreateTicket(notification);

            return notification.Ticket;
        }

        private ILogger Logger => Options.Logger;
    }
}
