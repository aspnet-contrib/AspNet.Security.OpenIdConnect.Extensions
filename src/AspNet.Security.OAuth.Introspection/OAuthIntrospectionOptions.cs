/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/aspnet-contrib/AspNet.Security.OAuth.Extensions for more information
 * concerning the license and the contributors participating to this project.
 */

using System.Collections.Generic;
using System.Net.Http;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.Caching.Distributed;

namespace AspNet.Security.OAuth.Introspection {
    public class OAuthIntrospectionOptions : AuthenticationOptions {
        public OAuthIntrospectionOptions() {
            AuthenticationScheme = OAuthIntrospectionDefaults.AuthenticationScheme;
        }

        /// <summary>
        /// Gets or sets the intended audiences of this resource server.
        /// Setting this property is recommended when the authorization
        /// server issues access tokens for multiple distinct resource servers.
        /// </summary>
        public IList<string> Audiences { get; } = new List<string>();

        /// <summary>
        /// Gets or sets the base address of the OAuth2/OpenID Connect server.
        /// </summary>
        public string Authority { get; set; }

        /// <summary>
        /// Gets or sets the address of the introspection endpoint.
        /// </summary>
        public string IntrospectionEndpoint { get; set; }

        /// <summary>
        /// Gets or sets the client identifier representing the resource server.
        /// </summary>
        public string ClientId { get; set; }

        /// <summary>
        /// Gets or sets the client secret used to
        /// communicate with the introspection endpoint.
        /// </summary>
        public string ClientSecret { get; set; }

        /// <summary>
        /// Gets or sets the cache used to store the authentication tickets
        /// resolved from the access tokens received by the resource server.
        /// </summary>
        public IDistributedCache Cache { get; set; }

        /// <summary>
        /// The object provided by the application to process events raised by the bearer authentication middleware.
        /// The application may implement the interface fully, or it may create an instance of OAuthIntrospectionEvents
        /// and assign delegates only to the events it wants to process.
        /// </summary>
        public IOAuthIntrospectionEvents Events { get; set; } = new OAuthIntrospectionEvents();

        /// <summary>
        /// Gets or sets the HTTP client used to communicate
        /// with the remote OAuth2/OpenID Connect server.
        /// </summary>
        public HttpClient HttpClient { get; set; } = new HttpClient();

        /// <summary>
        /// Gets or sets the clock used to determine the current date/time.
        /// </summary>
        public ISystemClock SystemClock { get; set; } = new SystemClock();

        /// <summary>
        /// Gets or sets the data format used to serialize and deserialize
        /// the authenticated tickets stored in the distributed cache.
        /// </summary>
        public ISecureDataFormat<AuthenticationTicket> AccessTokenFormat { get; set; }

        /// <summary>
        /// Gets or sets the data protection provider used to create the default
        /// data protectors used by <see cref="OAuthIntrospectionMiddleware"/>.
        /// When this property is set to <c>null</c>, the data protection provider
        /// is directly retrieved from the dependency injection container.
        /// </summary>
        public IDataProtectionProvider DataProtectionProvider { get; set; }
    }
}
