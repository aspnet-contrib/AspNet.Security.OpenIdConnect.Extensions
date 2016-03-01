﻿/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/aspnet-contrib/AspNet.Security.OAuth.Extensions for more information
 * concerning the license and the contributors participating to this project.
 */

using System.Collections.Generic;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Builder;
using AspNet.Security.OAuth.Validation.Events;

namespace AspNet.Security.OAuth.Validation
{
    public class OAuthValidationOptions : AuthenticationOptions
    {
        public OAuthValidationOptions()
        {
            AuthenticationScheme = OAuthValidationDefaults.AuthenticationScheme;
        }

        /// <summary>
        /// Gets or sets the intended audiences of this resource server.
        /// Setting this property is recommended when the authorization
        /// server issues access tokens for multiple distinct resource servers.
        /// </summary>
        public IList<string> Audiences { get; } = new List<string>();

        /// <summary>
        /// Gets or sets the clock used to determine the current date/time.
        /// </summary>
        public ISystemClock SystemClock { get; set; } = new SystemClock();

        /// <summary>
        /// Gets or sets the data format used to unprotect the
        /// authenticated tickets received by the validation middleware.
        /// </summary>
        public ISecureDataFormat<AuthenticationTicket> TicketFormat { get; set; }

        /// <summary>
        /// The object provided by the application to process events raised by the validation authentication middleware.
        /// The application may implement the interface fully, or it may create an instance of ValidationEvents
        /// and assign delegates only to the events it wants to process.
        /// </summary>
        public IValidationEvents Events { get; set; } = new ValidationEvents();
    }
}
