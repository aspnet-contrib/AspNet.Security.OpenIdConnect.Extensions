/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/aspnet-contrib/AspNet.Security.OAuth.Extensions for more information
 * concerning the license and the contributors participating to this project.
 */

using JetBrains.Annotations;
using Microsoft.Owin;
using Microsoft.Owin.Security;

namespace Owin.Security.OAuth.Validation {
    /// <summary>
    /// Allows customization of the token validation logic.
    /// </summary>
    public class ValidateTokenContext : BaseValidationContext {
        public ValidateTokenContext(
            [NotNull]IOwinContext context,
            [NotNull]OAuthValidationOptions options,
            [NotNull]AuthenticationTicket ticket)
            : base(context, options) {
            Ticket = ticket;
        }

        /// <summary>
        /// The <see cref="AuthenticationTicket"/> created from the introspection data.
        /// </summary>
        public AuthenticationTicket Ticket { get; }

        private bool _isValid { get; set; } = true;

        /// <summary>
        /// Indicates the ticket is valid.
        /// <remarks>
        /// Setting this property indicates to the middleware that token validation
        /// has been handled by the application.
        /// </remarks>
        /// </summary>
        public bool IsValid {
            get { return _isValid; }
            set {
                Handled = true;
                _isValid = value;
            }
        }
    }
}
