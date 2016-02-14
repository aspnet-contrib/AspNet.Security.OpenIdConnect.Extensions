/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/aspnet-contrib/AspNet.Security.OAuth.Extensions for more information
 * concerning the license and the contributors participating to this project.
 */

using System;
using System.Net.Http;
using System.Text.Encodings.Web;
using JetBrains.Annotations;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace AspNet.Security.OAuth.Introspection {
    public class OAuthIntrospectionMiddleware : AuthenticationMiddleware<OAuthIntrospectionOptions> {
        public OAuthIntrospectionMiddleware(
            [NotNull] RequestDelegate next,
            [NotNull] IOptions<OAuthIntrospectionOptions> options,
            [NotNull] ILoggerFactory loggerFactory,
            [NotNull] UrlEncoder encoder,
            [NotNull] IDistributedCache cache)
            : base(next, options, loggerFactory, encoder) {
            if (string.IsNullOrEmpty(Options.Authority) &&
                string.IsNullOrEmpty(Options.IntrospectionEndpoint)) {
                throw new ArgumentException("The authority or the introspection endpoint must be configured.", nameof(options));
            }

            if (string.IsNullOrEmpty(Options.ClientId) ||
                string.IsNullOrEmpty(Options.ClientSecret)) {
                throw new ArgumentException("Client credentials must be configured.", nameof(options));
            }

            if (Options.Cache == null) {
                Options.Cache = cache;
            }

            if (Options.HttpClient == null) {
                Options.HttpClient = new HttpClient {
                    Timeout = TimeSpan.FromSeconds(60),
                    MaxResponseContentBufferSize = 1024 * 1024 * 10
                };

                Options.HttpClient.DefaultRequestHeaders.UserAgent.ParseAdd("ASP.NET OAuth2 introspection middleware");
            }
        }

        protected override AuthenticationHandler<OAuthIntrospectionOptions> CreateHandler() {
            return new OAuthIntrospectionHandler();
        }
    }
}
