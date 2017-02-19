﻿using System;
using System.Threading;
using System.Threading.Tasks;
using JetBrains.Annotations;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Newtonsoft.Json;

namespace AspNet.Security.OAuth.Introspection
{
    /// <summary>
    /// Represents an OAuth2 introspection configuration.
    /// </summary>
    [JsonObject(MemberSerialization = MemberSerialization.OptIn)]
    public class OAuthIntrospectionConfiguration : OpenIdConnectConfiguration
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="OAuthIntrospectionConfiguration"/> class.
        /// </summary>
        public OAuthIntrospectionConfiguration()
            : base() { }

        /// <summary>
        /// Initializes a new instance of the <see cref="OAuthIntrospectionConfiguration"/> class.
        /// </summary>
        /// <param name="json">The JSON payload used to initialize the current instance.</param>
        public OAuthIntrospectionConfiguration([NotNull] string json)
            : base(json) { }

        /// <summary>
        /// Gets or sets the introspection endpoint address.
        /// </summary>
        [JsonProperty(
            DefaultValueHandling = DefaultValueHandling.Ignore,
            NullValueHandling = NullValueHandling.Ignore,
            PropertyName = OAuthIntrospectionConstants.Metadata.IntrospectionEndpoint)]
        public string IntrospectionEndpoint { get; set; }

        /// <summary>
        /// Represents a configuration retriever able to deserialize
        /// <see cref="OAuthIntrospectionConfiguration"/> instances.
        /// </summary>
        public class Retriever : IConfigurationRetriever<OAuthIntrospectionConfiguration>
        {
            /// <summary>
            /// Retrieves the OAuth2 introspection configuration from the specified address.
            /// </summary>
            /// <param name="address">The address of the discovery document.</param>
            /// <param name="retriever">The object used to retrieve the discovery document.</param>
            /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
            /// <returns>An <see cref="OAuthIntrospectionConfiguration"/> instance.</returns>
            public async Task<OAuthIntrospectionConfiguration> GetConfigurationAsync(
                [NotNull] string address, [NotNull] IDocumentRetriever retriever, CancellationToken cancellationToken)
            {
                if (string.IsNullOrEmpty(address))
                {
                    throw new ArgumentException("The address cannot be null or empty.", nameof(address));
                }

                if (retriever == null)
                {
                    throw new ArgumentNullException(nameof(retriever));
                }

                return new OAuthIntrospectionConfiguration(await retriever.GetDocumentAsync(address, cancellationToken));
            }
        }
    }
}
