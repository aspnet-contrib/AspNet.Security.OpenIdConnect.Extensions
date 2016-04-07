/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/aspnet-contrib/AspNet.Security.OAuth.Extensions for more information
 * concerning the license and the contributors participating to this project.
 */

using JetBrains.Annotations;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;

namespace AspNet.Security.OAuth.Introspection {
    /// <summary>
    /// Base class for all introspection events that holds common properties.
    /// </summary>
    public abstract class BaseIntrospectionContext : BaseContext {
        public BaseIntrospectionContext(
            [NotNull]HttpContext context, 
            [NotNull]OAuthIntrospectionOptions options) 
            : base(context) {
            Options = options;
        }

        /// <summary>
        /// Indicates the application has handled the event process.
        /// </summary>
        internal bool Handled { get; set; }

        /// <summary>
        /// The middleware Options.
        /// </summary>
        public OAuthIntrospectionOptions Options { get; }
    }
}
