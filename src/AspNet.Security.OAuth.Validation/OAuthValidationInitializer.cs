/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/aspnet-contrib/AspNet.Security.OAuth.Extensions for more information
 * concerning the license and the contributors participating to this project.
 */

using System;
using System.ComponentModel;
using JetBrains.Annotations;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.Options;

namespace AspNet.Security.OAuth.Validation
{
    /// <summary>
    /// Contains the methods required to ensure that the configuration used by
    /// the OAuth2 validation handler is in a consistent and valid state.
    /// </summary>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public class OAuthValidationInitializer : IPostConfigureOptions<OAuthValidationOptions>
    {
        private readonly IDataProtectionProvider _dataProtectionProvider;

        /// <summary>
        /// Creates a new instance of the <see cref="OAuthValidationInitializer"/> class.
        /// </summary>
        public OAuthValidationInitializer([NotNull] IDataProtectionProvider dataProtectionProvider)
        {
            _dataProtectionProvider = dataProtectionProvider;
        }

        /// <summary>
        /// Populates the default OAuth2 validation options and ensure
        /// that the configuration is in a consistent and valid state.
        /// </summary>
        /// <param name="name">The authentication scheme associated with the handler instance.</param>
        /// <param name="options">The options instance to initialize.</param>
        public void PostConfigure([NotNull] string name, [NotNull] OAuthValidationOptions options)
        {
            if (options == null)
            {
                throw new ArgumentNullException(nameof(options));
            }

            if (string.IsNullOrEmpty(name))
            {
                throw new ArgumentException("The options instance name cannot be null or empty.", nameof(name));
            }

            if (options.Events == null)
            {
                options.Events = new OAuthValidationEvents();
            }

            if (options.DataProtectionProvider == null)
            {
                options.DataProtectionProvider = _dataProtectionProvider;
            }

            if (options.AccessTokenFormat == null)
            {
                // Note: the following purposes must match the ones used by the OpenID Connect server middleware.
                var protector = options.DataProtectionProvider.CreateProtector(
                    "OpenIdConnectServerHandler", nameof(options.AccessTokenFormat), name);

                options.AccessTokenFormat = new TicketDataFormat(protector);
            }
        }
    }
}
