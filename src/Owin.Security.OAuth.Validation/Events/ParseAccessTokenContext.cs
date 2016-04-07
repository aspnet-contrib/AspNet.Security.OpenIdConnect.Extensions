/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/aspnet-contrib/AspNet.Security.OAuth.Extensions for more information
 * concerning the license and the contributors participating to this project.
 */

using JetBrains.Annotations;
using Microsoft.Owin;

namespace Owin.Security.OAuth.Validation {
    /// <summary>
    /// Allows custom parsing of access tokens from requests.
    /// </summary>
    public class ParseAccessTokenContext : BaseValidationContext {
        public ParseAccessTokenContext(
            [NotNull]IOwinContext context,
            [NotNull]OAuthValidationOptions options)
            : base(context, options) {
        }

        private string _token { get; set; }

        /// <summary>
        /// Gets or sets the access token.
        /// <remarks>
        /// Setting this property indicates to the middleware that the request has been processed
        /// and a token extracted. Setting this to null will invalidate the token.
        /// </remarks>
        /// </summary>
        public string Token {
            get { return _token; }
            set {
                Handled = true;
                _token = value;
            }
        }
    }
}
