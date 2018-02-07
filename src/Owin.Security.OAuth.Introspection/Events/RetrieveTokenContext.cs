/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/aspnet-contrib/AspNet.Security.OAuth.Extensions for more information
 * concerning the license and the contributors participating to this project.
 */

using JetBrains.Annotations;
using Microsoft.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Provider;

namespace Owin.Security.OAuth.Introspection
{
    /// <summary>
    /// Allows custom parsing of access tokens from requests.
    /// </summary>
    public class RetrieveTokenContext : BaseContext<OAuthIntrospectionOptions>
    {
        public RetrieveTokenContext(
            [NotNull] IOwinContext context,
            [NotNull] OAuthIntrospectionOptions options)
            : base(context, options)
        {
        }

        /// <summary>
        /// Gets or sets the access token.
        /// </summary>
        public string Token { get; set; }

        /// <summary>
        /// Gets or sets the <see cref="AuthenticationTicket"/> created by the application.
        /// </summary>
        public AuthenticationTicket Ticket { get; set; }

        /// <summary>
        /// Gets a boolean indicating if the operation was handled from user code.
        /// </summary>
        public bool Handled { get; private set; }

        /// <summary>
        /// Marks the operation as handled to prevent the default logic from being applied.
        /// </summary>
        public void HandleValidation() => Handled = true;

        /// <summary>
        /// Marks the operation as handled to prevent the default logic from being applied.
        /// </summary>
        /// <param name="ticket">The authentication ticket to use.</param>
        public void HandleValidation(AuthenticationTicket ticket)
        {
            Ticket = ticket;
            Handled = true;
        }
    }
}
