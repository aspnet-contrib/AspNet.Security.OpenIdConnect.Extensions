/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/aspnet-contrib/AspNet.Security.OAuth.Extensions for more information
 * concerning the license and the contributors participating to this project.
 */

using System;
using System.Collections.Generic;
using System.Net.Http;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.IdentityModel.Protocols;

namespace AspNet.Security.OAuth.Introspection
{
    /// <summary>
    /// Exposes various settings needed to control
    /// the behavior of the introspection middleware.
    /// </summary>
    public class OAuthIntrospectionOptions : AuthenticationSchemeOptions
    {
        /// <summary>
        /// Creates a new instance of the <see cref="OAuthIntrospectionOptions"/> class.
        /// </summary>
        public OAuthIntrospectionOptions()
        {
            Events = new OAuthIntrospectionEvents();
        }

        /// <summary>
        /// Gets the intended audiences of this resource server.
        /// Setting this property is recommended when the authorization
        /// server issues access tokens for multiple distinct resource servers.
        /// </summary>
        public ISet<string> Audiences { get; } = new HashSet<string>(StringComparer.Ordinal);

        /// <summary>
        /// Gets or sets the absolute URL of the OAuth2/OpenID Connect server.
        /// Note: this property is ignored when <see cref="Configuration"/>
        /// or <see cref="ConfigurationManager"/> are set.
        /// </summary>
        public Uri Authority { get; set; }

        /// <summary>
        /// Gets or sets the URL of the OAuth2/OpenID Connect server discovery endpoint.
        /// When the URL is relative, <see cref="Authority"/> must be set and absolute.
        /// Note: this property is ignored when <see cref="Configuration"/>
        /// or <see cref="ConfigurationManager"/> are set.
        /// </summary>
        public Uri MetadataAddress { get; set; }

        /// <summary>
        /// Gets or sets a boolean indicating whether HTTPS is required to retrieve the metadata document.
        /// The default value is <c>true</c>. This option should be used only in development environments.
        /// Note: this property is ignored when <see cref="Configuration"/> or <see cref="ConfigurationManager"/> are set.
        /// </summary>
        public bool RequireHttpsMetadata { get; set; } = true;

        /// <summary>
        /// Gets or sets the configuration used by the introspection middleware.
        /// Note: this property is ignored when <see cref="ConfigurationManager"/> is set.
        /// </summary>
        public OAuthIntrospectionConfiguration Configuration { get; set; }

        /// <summary>
        /// Gets or sets the configuration manager used by the introspection middleware.
        /// </summary>
        public IConfigurationManager<OAuthIntrospectionConfiguration> ConfigurationManager { get; set; }

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
        /// Gets or sets the optional "realm" value returned to
        /// the caller as part of the WWW-Authenticate header.
        /// </summary>
        public string Realm { get; set; }

        /// <summary>
        /// Gets or sets a boolean determining whether the access token should be stored in the
        /// <see cref="AuthenticationProperties"/> after a successful authentication process.
        /// </summary>
        public bool SaveToken { get; set; } = true;

        /// <summary>
        /// Gets or sets a boolean determining whether the token validation errors should be returned to the caller.
        /// Enabled by default, this option can be disabled to prevent the introspection middleware from returning
        /// an error, an error_description and/or an error_uri in the WWW-Authenticate header.
        /// </summary>
        public bool IncludeErrorDetails { get; set; } = true;

        /// <summary>
        /// Gets or sets the claim type used for the name claim.
        /// By default, the standard <see cref="OAuthIntrospectionConstants.Claims.Name"/>
        /// claim defined by the OAuth2 introspection specification is used.
        /// </summary>
        public string NameClaimType { get; set; } = OAuthIntrospectionConstants.Claims.Name;

        /// <summary>
        /// Gets or sets the claim type used for the role claim(s).
        /// By default, <see cref="OAuthIntrospectionConstants.Claims.Role"/> is used.
        /// </summary>
        public string RoleClaimType { get; set; } = OAuthIntrospectionConstants.Claims.Role;

        /// <summary>
        /// Gets or sets the cache used to store the access tokens/authentication tickets
        /// and the introspection responses returned received by the resource server.
        /// </summary>
        public IDistributedCache Cache { get; set; }

        /// <summary>
        /// Gets or sets the caching policy used to determine
        /// how long the introspection responses should be cached.
        /// Note: this property can be set to <c>null</c> to
        /// prevent the introspection responses from being cached.
        /// </summary>
        public DistributedCacheEntryOptions CachingPolicy { get; set; } = new DistributedCacheEntryOptions
        {
            AbsoluteExpirationRelativeToNow = TimeSpan.FromMinutes(15)
        };

        /// <summary>
        /// Gets or sets the object provided by the application to process events raised by the authentication middleware.
        /// The application may implement the interface fully, or it may create an instance of
        /// <see cref="OAuthIntrospectionEvents"/> and assign delegates only to the events it wants to process.
        /// </summary>
        public new OAuthIntrospectionEvents Events
        {
            get => (OAuthIntrospectionEvents) base.Events;
            set => base.Events = value;
        }

        /// <summary>
        /// Copy Http Headers that match the provided values from the request being authenticated to the Introspection request.
        /// </summary>
        /// <param name="exactMatches">List of strings that are matched to the Http Headers exactly.</param>
        /// <param name="prefixes">List of strings that Http Headers are compared to, e.g. "X-" for X-Forwarded or X-Correlation-Id.</param>
        public void SetValuesToMatchFromRequestHttpHeaders(string[] exactMatches, string[] prefixes)
        {
            IncludeHttpHeadersFromRequest = (exactMatches?.Length > 0 || prefixes?.Length > 0);

            MatchingHttpHeadersPrefixes = prefixes ?? new string[0];
            MatchingHttpHeadersExact = exactMatches ?? new string[0];
        }

        /// <summary>
        /// Property that returns whether Http Headers that match either the exact or prefix values will be copied or not.  To set
        /// this property to false, call method SetValuesToMatchFromRequestHttpHeaders with an empty string.
        /// </summary>
        public bool IncludeHttpHeadersFromRequest { get; private set; }

        /// <summary>
        /// Property that returns the prefix to use to match Http Headers.
        /// </summary>
        public string[] MatchingHttpHeadersPrefixes { get; private set; }

        /// <summary>
        /// Property that returns the exatc matches to use when matching Http Headers.
        /// </summary>
        public string[] MatchingHttpHeadersExact { get; private set; }

        /// <summary>
        /// Gets or sets the HTTP client used to communicate with the remote OAuth2 server.
        /// </summary>
        public HttpClient HttpClient { get; set; }

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
        /// data protectors used by the OAuth2 introspection handler.
        /// When this property is set to <c>null</c>, the data protection provider
        /// is directly retrieved from the dependency injection container.
        /// </summary>
        public IDataProtectionProvider DataProtectionProvider { get; set; }
    }
}
