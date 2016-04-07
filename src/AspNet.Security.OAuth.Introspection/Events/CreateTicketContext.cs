/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/aspnet-contrib/AspNet.Security.OAuth.Extensions for more information
 * concerning the license and the contributors participating to this project.
 */

using JetBrains.Annotations;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Newtonsoft.Json.Linq;

namespace AspNet.Security.OAuth.Introspection {
    /// <summary>
    /// Allows interception of the AuthenticationTicket creation process.
    /// </summary>
    public class CreateTicketContext : BaseIntrospectionContext {
        public CreateTicketContext(
            [NotNull]HttpContext context,
            [NotNull]OAuthIntrospectionOptions options,
            [NotNull]JObject payload)
            : base(context, options) {
            Payload = payload;
        }

        /// <summary>
        /// The payload from the introspection request to the authorization server.
        /// </summary>
        public JObject Payload { get; }

        private AuthenticationTicket _ticket { get; set; }

        /// <summary>
        /// An <see cref="AuthenticationTicket"/> created by the application.
        /// <remarks>
        /// Set this property to indicate that the application has handled the creation of the
        /// ticket. Set this property to null to instruct the middleware there was a failure
        /// during ticket creation.
        /// </remarks>
        /// </summary>
        public AuthenticationTicket Ticket {
            get { return _ticket; }
            set {
                Handled = true;
                _ticket = value;
            }
        }
    }
}
