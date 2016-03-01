/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/aspnet-contrib/AspNet.Security.OAuth.Extensions for more information
 * concerning the license and the contributors participating to this project.
 */

using System.Net.Http;
using JetBrains.Annotations;
using Newtonsoft.Json.Linq;
using Microsoft.Owin;

namespace Owin.Security.OAuth.Introspection {
    /// <summary>
    /// Allows for custom handling of the call to the Authorization Server's Introspection endpoint.
    /// </summary>
    public class RequestTokenIntrospectionContext : BaseIntrospectionContext {
        public RequestTokenIntrospectionContext(
            [NotNull]IOwinContext context,
            [NotNull]OAuthIntrospectionOptions options,
            [NotNull]string token)
            : base(context, options) {
            Token = token;
        }

        /// <summary>
        /// An <see cref="HttpClient"/> for use by the application to call the authorization server.
        /// </summary>
        public HttpClient Client => Options.HttpClient;

        /// <summary>
        /// The access token parsed from the client request.
        /// </summary>
        public string Token { get; }

        private JObject _payload { get; set; }

        /// <summary>
        /// The data retrieved from the call to the introspection endpoint on the authorization server.
        /// <remarks>
        /// Set this property to indicate that the introspection call was handled
        /// by the application. Set this property to null to instruct the middleware
        /// to indicate a failure.
        /// </remarks>
        /// </summary>
        public JObject Payload {
            get { return _payload; }
            set {
                Handled = true;
                Payload = value;
            }
        }
    }
}
