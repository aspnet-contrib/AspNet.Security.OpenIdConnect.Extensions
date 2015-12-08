/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/aspnet-contrib/AspNet.Security.OAuth.Extensions for more information
 * concerning the license and the contributors participating to this project.
 */

using System;
using AspNet.Security.OAuth.Validation;
using Microsoft.Extensions.Internal;

namespace Microsoft.AspNet.Builder {
    /// <summary>
    /// Provides extension methods used to configure the OAuth2
    /// validation middleware in an ASP.NET 5 pipeline.
    /// </summary>
    public static class OAuthValidationExtensions {
        /// <summary>
        /// Adds a new instance of the OAuth2 validation middleware in the ASP.NET 5 pipeline.
        /// </summary>
        /// <param name="app">The application builder.</param>
        /// <param name="configuration">The delegate used to configure the validation options.</param>
        /// <returns>The application builder.</returns>
        public static IApplicationBuilder UseOAuthValidation(
            [NotNull] this IApplicationBuilder app,
            [NotNull] Action<OAuthValidationOptions> configuration) {
            if (app == null) {
                throw new ArgumentNullException(nameof(app));
            }

            if (configuration == null) {
                throw new ArgumentNullException(nameof(configuration));
            }

            var options = new OAuthValidationOptions();
            configuration(options);

            return app.UseOAuthValidation(options);
        }

        /// <summary>
        /// Adds a new instance of the OAuth2 validation middleware in the ASP.NET 5 pipeline.
        /// </summary>
        /// <param name="app">The application builder.</param>
        /// <param name="options">The options used to configure the validation middleware.</param>
        /// <returns>The application builder.</returns>
        public static IApplicationBuilder UseOAuthValidation(
            [NotNull] this IApplicationBuilder app,
            [NotNull] OAuthValidationOptions options) {
            if (app == null) {
                throw new ArgumentNullException(nameof(app));
            }

            if (options == null) {
                throw new ArgumentNullException(nameof(options));
            }

            return app.UseMiddleware<OAuthValidationMiddleware>(options);
        }
    }
}
