/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/aspnet-contrib/AspNet.Security.OAuth.Extensions for more information
 * concerning the license and the contributors participating to this project.
 */

using System.Collections.Generic;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.Logging;
using Microsoft.Owin.Infrastructure;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Infrastructure;
using System;

namespace Owin.Security.OAuth.Validation {
    public class OAuthValidationOptions : AuthenticationOptions {
        public OAuthValidationOptions()
            : base(OAuthValidationDefaults.AuthenticationScheme) {
            AuthenticationMode = AuthenticationMode.Active;
        }

        /// <summary>
        /// Gets or sets the intended audiences of this resource server.
        /// Setting this property is recommended when the authorization
        /// server issues access tokens for multiple distinct resource servers.
        /// </summary>
        public IList<string> Audiences { get; } = new List<string>();

        /// <summary>
        /// Gets or sets a boolean determining whether the access token should be stored in the
        /// <see cref="AuthenticationProperties"/> after a successful authentication process.
        /// </summary>
        public bool SaveToken { get; set; } = true;

        /// <summary>
        /// Gets or sets the logger used by <see cref="OAuthValidationMiddleware"/>.
        /// When unassigned, a default instance is created using the logger factory.
        /// </summary>
        public ILogger Logger { get; set; }

        /// <summary>
        /// Gets or sets the clock used to determine the current date/time.
        /// </summary>
        public ISystemClock SystemClock { get; set; } = new SystemClock();

        /// <summary>
        /// Gets or sets the data format used to unprotect the
        /// access tokens received by the validation middleware.
        /// </summary>
        public ISecureDataFormat<AuthenticationTicket> AccessTokenFormat { get; set; }

        /// <summary>
        /// Gets or sets the data protection provider used to create the default
        /// data protector used by <see cref="OAuthValidationMiddleware"/>.
        /// </summary>
        public IDataProtectionProvider DataProtectionProvider { get; set; }

        /// <summary>
        /// Gets or sets the object provided by the application to process events raised by the authentication middleware.
        /// The application may implement the interface fully, or it may create an instance of
        /// <see cref="OAuthValidationEvents"/> and assign delegates only to the events it wants to process.
        /// </summary>
        public OAuthValidationEvents Events { get; set; } = new OAuthValidationEvents();

        /// <summary>
        /// Allow to use custom Validation Handler. For example to override HandleUnauthorizedAsync and customize response.
        /// </summary>
        public Func<AuthenticationHandler<OAuthValidationOptions>> Handler { get; set; }
    }
}
