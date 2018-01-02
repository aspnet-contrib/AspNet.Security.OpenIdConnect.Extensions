/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/aspnet-contrib/AspNet.Security.OAuth.Extensions for more information
 * concerning the license and the contributors participating to this project.
 */

using System;
using System.ComponentModel;
using AspNet.Security.OAuth.Introspection;
using JetBrains.Annotations;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;

namespace Microsoft.Extensions.DependencyInjection
{
    /// <summary>
    /// Provides extension methods used to configure the OAuth2
    /// introspection middleware in an ASP.NET Core pipeline.
    /// </summary>
    public static class OAuthIntrospectionExtensions
    {
        /// <summary>
        /// Adds a new instance of the OAuth2 introspection middleware in the ASP.NET Core pipeline.
        /// </summary>
        /// <param name="builder">The authentication builder.</param>
        /// <returns>The authentication builder.</returns>
        public static AuthenticationBuilder AddOAuthIntrospection([NotNull] this AuthenticationBuilder builder)
        {
            return builder.AddOAuthIntrospection(OAuthIntrospectionDefaults.AuthenticationScheme);
        }

        /// <summary>
        /// Adds a new instance of the OAuth2 introspection middleware in the ASP.NET Core pipeline.
        /// </summary>
        /// <param name="builder">The authentication builder.</param>
        /// <param name="configuration">The delegate used to configure the introspection options.</param>
        /// <returns>The authentication builder.</returns>
        public static AuthenticationBuilder AddOAuthIntrospection(
            [NotNull] this AuthenticationBuilder builder,
            [NotNull] Action<OAuthIntrospectionOptions> configuration)
        {
            return builder.AddOAuthIntrospection(OAuthIntrospectionDefaults.AuthenticationScheme, configuration);
        }

        /// <summary>
        /// Adds a new instance of the OAuth2 introspection middleware in the ASP.NET Core pipeline.
        /// </summary>
        /// <param name="builder">The authentication builder.</param>
        /// <param name="scheme">The authentication scheme associated with this instance.</param>
        /// <returns>The authentication builder.</returns>
        [EditorBrowsable(EditorBrowsableState.Advanced)]
        public static AuthenticationBuilder AddOAuthIntrospection(
            [NotNull] this AuthenticationBuilder builder, [NotNull] string scheme)
        {
            return builder.AddOAuthIntrospection(scheme, options => { });
        }

        /// <summary>
        /// Adds a new instance of the OAuth2 introspection middleware in the ASP.NET Core pipeline.
        /// </summary>
        /// <param name="builder">The authentication builder.</param>
        /// <param name="scheme">The authentication scheme associated with this instance.</param>
        /// <param name="configuration">The delegate used to configure the introspection options.</param>
        /// <returns>The authentication builder.</returns>
        [EditorBrowsable(EditorBrowsableState.Advanced)]
        public static AuthenticationBuilder AddOAuthIntrospection(
            [NotNull] this AuthenticationBuilder builder, [NotNull] string scheme,
            [NotNull] Action<OAuthIntrospectionOptions> configuration)
        {
            if (builder == null)
            {
                throw new ArgumentNullException(nameof(builder));
            }

            if (configuration == null)
            {
                throw new ArgumentNullException(nameof(configuration));
            }

            if (string.IsNullOrEmpty(scheme))
            {
                throw new ArgumentException("The scheme cannot be null or empty.", nameof(scheme));
            }

            // Note: TryAddEnumerable() is used here to ensure the initializer is only registered once.
            builder.Services.TryAddEnumerable(
                ServiceDescriptor.Singleton<IPostConfigureOptions<OAuthIntrospectionOptions>,
                                            OAuthIntrospectionInitializer>());
            if(HasClaimIssuer(configuration))
                builder.Services.AddTransient<IClaimsTransformation, OAuthClaimTransformer>();

            return builder.AddScheme<OAuthIntrospectionOptions, OAuthIntrospectionHandler>(scheme, configuration);
        }

        private static bool HasClaimIssuer(Action<OAuthIntrospectionOptions> configuration)
        {
            var oAuthIntrospectionOptions = new OAuthIntrospectionOptions();
            configuration(oAuthIntrospectionOptions);

            return !string.IsNullOrEmpty(oAuthIntrospectionOptions.ClaimsIssuer);
        }
    }
}
