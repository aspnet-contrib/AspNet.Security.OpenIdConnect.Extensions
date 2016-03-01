/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/aspnet-contrib/AspNet.Security.OAuth.Extensions for more information
 * concerning the license and the contributors participating to this project.
 */

using System;
using System.Threading.Tasks;

namespace AspNet.Security.OAuth.Introspection {
    /// <summary>
    /// Allows customization of introspection handling within the middleware.
    /// </summary>
    public class OAuthIntrospectionEvents : IOAuthIntrospectionEvents {
        /// <summary>
        /// Invoked when a ticket is to be created from an introspection response.
        /// </summary>
        public Func<CreateTicketContext, Task> OnCreateTicket { get; set; } = context => Task.FromResult(0);

        /// <summary>
        /// Invoked when a token is to be parsed from a newly-received request.
        /// </summary>
        public Func<ParseAccessTokenContext, Task> OnParseAccessToken { get; set; } = context => Task.FromResult(0);

        /// <summary>
        /// Invoked when a token is to be sent to the authorization server for introspection.
        /// </summary>
        public Func<RequestTokenIntrospectionContext, Task> OnRequestTokenIntrospection { get; set; } = context => Task.FromResult(0);

        /// <summary>
        /// Invoked when a token is to be validated, before final processing.
        /// </summary>
        public Func<ValidateTokenContext, Task> OnValidateToken { get; set; } = context => Task.FromResult(0);

        /// <summary>
        /// Invoked when a ticket is to be created from an introspection response.
        /// </summary>
        public virtual Task CreateTicket(CreateTicketContext context) => OnCreateTicket(context);

        /// <summary>
        /// Invoked when a token is to be parsed from a newly-received request.
        /// </summary>
        public virtual Task ParseAccessToken(ParseAccessTokenContext context) => OnParseAccessToken(context);

        /// <summary>
        /// Invoked when a token is to be sent to the authorization server for introspection.
        /// </summary>
        public virtual Task RequestTokenIntrospection(RequestTokenIntrospectionContext context) => OnRequestTokenIntrospection(context);

        /// <summary>
        /// Invoked when a token is to be validated, before final processing.
        /// </summary>
        public virtual Task ValidateToken(ValidateTokenContext context) => OnValidateToken(context);
    }
}
