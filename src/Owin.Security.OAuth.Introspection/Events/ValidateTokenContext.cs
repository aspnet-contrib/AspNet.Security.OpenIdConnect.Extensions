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
    /// Allows customization of the token validation logic.
    /// </summary>
    public class ValidateTokenContext : BaseContext<OAuthIntrospectionOptions>
    {
        public ValidateTokenContext(
            [NotNull] IOwinContext context,
            [NotNull] OAuthIntrospectionOptions options,
            [NotNull] AuthenticationTicket ticket)
            : base(context, options)
        {
            Ticket = ticket;
        }

        /// <summary>
        /// Gets or sets the <see cref="AuthenticationTicket"/>
        /// created from the introspection response.
        /// </summary>
        public AuthenticationTicket Ticket { get; set; }
    }
}
