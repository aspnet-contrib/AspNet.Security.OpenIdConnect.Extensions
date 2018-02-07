/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/aspnet-contrib/AspNet.Security.OAuth.Extensions for more information
 * concerning the license and the contributors participating to this project.
 */

using System.Net.Http;
using JetBrains.Annotations;
using Microsoft.Owin;
using Microsoft.Owin.Security.Provider;

namespace Owin.Security.OAuth.Introspection
{
    /// <summary>
    /// Allows for custom handling of the call to the Authorization Server's Introspection endpoint.
    /// </summary>
    public class SendIntrospectionRequestContext : BaseContext<OAuthIntrospectionOptions>
    {
        public SendIntrospectionRequestContext(
            [NotNull] IOwinContext context,
            [NotNull] OAuthIntrospectionOptions options,
            [NotNull] HttpRequestMessage request,
            [NotNull] string token)
            : base(context, options)
        {
            Request = request;
            Token = token;
        }

        /// <summary>
        /// An <see cref="HttpClient"/> for use by the application to call the authorization server.
        /// </summary>
        public HttpClient Client => Options.HttpClient;

        /// <summary>
        /// Gets the HTTP request sent to the introspection endpoint.
        /// </summary>
        public new HttpRequestMessage Request { get; }

        /// <summary>
        /// Gets or sets the HTTP response returned by the introspection endpoint.
        /// </summary>
        public new HttpResponseMessage Response { get; set; }

        /// <summary>
        /// The access token parsed from the client request.
        /// </summary>
        public string Token { get; }

        /// <summary>
        /// Gets a boolean indicating if the operation was handled from user code.
        /// </summary>
        public bool Handled { get; private set; }

        /// <summary>
        /// Marks the operation as handled to prevent the default logic from being applied.
        /// </summary>
        public void HandleResponse() => Handled = true;
    }
}
