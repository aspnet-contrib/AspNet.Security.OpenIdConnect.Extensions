/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/aspnet-contrib/AspNet.Security.OAuth.Extensions for more information
 * concerning the license and the contributors participating to this project.
 */

using JetBrains.Annotations;
using Microsoft.Owin;
using Microsoft.Owin.Security.Provider;

namespace Owin.Security.OAuth.Introspection
{
    /// <summary>
    /// Base class for all introspection events that holds common properties.
    /// </summary>
    public abstract class BaseIntrospectionContext : BaseContext<OAuthIntrospectionOptions> {
        public BaseIntrospectionContext(
            [NotNull]IOwinContext context, 
            [NotNull]OAuthIntrospectionOptions options) 
            : base(context, options) {
        }

        /// <summary>
        /// Indicates the application has handled the event process.
        /// </summary>
        internal bool Handled { get; set; }
    }
}
