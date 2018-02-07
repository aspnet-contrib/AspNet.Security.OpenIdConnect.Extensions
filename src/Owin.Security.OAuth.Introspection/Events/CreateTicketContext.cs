/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/aspnet-contrib/AspNet.Security.OAuth.Extensions for more information
 * concerning the license and the contributors participating to this project.
 */

using JetBrains.Annotations;
using Microsoft.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Provider;
using Newtonsoft.Json.Linq;

namespace Owin.Security.OAuth.Introspection
{
    /// <summary>
    /// Allows interception of the AuthenticationTicket creation process.
    /// </summary>
    public class CreateTicketContext : BaseContext<OAuthIntrospectionOptions>
    {
        public CreateTicketContext(
            [NotNull] IOwinContext context,
            [NotNull] OAuthIntrospectionOptions options,
            [NotNull] AuthenticationTicket ticket,
            [NotNull] JObject payload)
            : base(context, options)
        {
            Ticket = ticket;
            Payload = payload;
        }

        /// <summary>
        /// Gets the payload extracted from the introspection response.
        /// </summary>
        public JObject Payload { get; }

        /// <summary>
        /// Gets or sets the <see cref="AuthenticationTicket"/> created by the application.
        /// </summary>
        public AuthenticationTicket Ticket { get; set; }
    }
}
