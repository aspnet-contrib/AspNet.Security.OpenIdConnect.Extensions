/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/aspnet-contrib/AspNet.Security.OAuth.Extensions for more information
 * concerning the license and the contributors participating to this project.
 */

using System.Threading.Tasks;

namespace Owin.Security.OAuth.Introspection {
    /// <summary>
    /// Allows customization of introspection handling within the middleware.
    /// </summary>
    public interface IOAuthIntrospectionEvents {
        /// <summary>
        /// Invoked when a ticket is to be created from an introspection response.
        /// </summary>
        Task CreateTicket(CreateTicketContext context);

        /// <summary>
        /// Invoked when a token is to be parsed from a newly-received request.
        /// </summary>
        Task ParseAccessToken(ParseAccessTokenContext context);

        /// <summary>
        /// Invoked when a token is to be sent to the authorization server for introspection.
        /// </summary>
        Task RequestTokenIntrospection(RequestTokenIntrospectionContext context);

        /// <summary>
        /// Invoked when a token is to be validated, before final processing.
        /// </summary>
        Task ValidateToken(ValidateTokenContext context);
    }
}
