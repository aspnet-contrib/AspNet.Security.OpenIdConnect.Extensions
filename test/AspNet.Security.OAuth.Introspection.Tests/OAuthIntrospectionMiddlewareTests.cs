/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/aspnet-contrib/AspNet.Security.OAuth.Extensions for more information
 * concerning the license and the contributors participating to this project.
 */

using System;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Threading.Tasks;
using AspNet.Security.OpenIdConnect.Extensions;
using AspNet.Security.OpenIdConnect.Server;
using Microsoft.AspNet.Authentication;
using Microsoft.AspNet.Builder;
using Microsoft.AspNet.Hosting;
using Microsoft.AspNet.Http;
using Microsoft.AspNet.Http.Authentication;
using Microsoft.AspNet.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Xunit;

namespace AspNet.Security.OAuth.Introspection.Tests {
    public class OAuthIntrospectionMiddlewareTests {
        [Fact]
        public void MissingAuthorityThrowsAnException() {
            // Arrange, act, assert
            var exception = Assert.Throws<ArgumentException>(() => CreateResourceServer(options => {
                options.Authority = null;
            }));

            Assert.Equal("options", exception.ParamName);
            Assert.StartsWith("The authority or the introspection endpoint must be configured.", exception.Message);
        }

        [Fact]
        public void MissingCredentialsThrowAnException() {
            // Arrange, act, assert
            var exception = Assert.Throws<ArgumentException>(() => CreateResourceServer(options => {
                options.Authority = "http://www.fabrikam.com/";
            }));

            Assert.Equal("options", exception.ParamName);
            Assert.StartsWith("Client credentials must be configured.", exception.Message);
        }

        [Fact]
        public async Task MissingTokenCausesInvalidAuthentication() {
            // Arrange
            var server = CreateResourceServer(options => {
                options.ClientId = "Fabrikam";
                options.ClientSecret = "B4657E03-D619";
            });

            var client = server.CreateClient();

            var request = new HttpRequestMessage(HttpMethod.Get, "/");

            // Act
            var response = await client.SendAsync(request);

            // Assert
            Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        }

        [Fact]
        public async Task InvalidTokenCausesInvalidAuthentication() {
            // Arrange
            var server = CreateResourceServer(options => {
                options.ClientId = "Fabrikam";
                options.ClientSecret = "B4657E03-D619";
            });

            var client = server.CreateClient();

            var request = new HttpRequestMessage(HttpMethod.Get, "/");
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", "invalid-token");

            // Act
            var response = await client.SendAsync(request);

            // Assert
            Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        }

        [Fact]
        public async Task ValidTokenAllowsSuccessfulAuthentication() {
            // Arrange
            var server = CreateResourceServer(options => {
                options.ClientId = "Fabrikam";
                options.ClientSecret = "B4657E03-D619";
            });

            var client = server.CreateClient();

            var request = new HttpRequestMessage(HttpMethod.Get, "/");
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", "token-1");

            // Act
            var response = await client.SendAsync(request);

            // Assert
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            Assert.Equal("Fabrikam", await response.Content.ReadAsStringAsync());
        }

        [Fact]
        public async Task MissingAudienceCausesInvalidAuthentication() {
            // Arrange
            var server = CreateResourceServer(options => {
                options.Audience = "http://www.fabrikam.com/";
                options.ClientId = "Fabrikam";
                options.ClientSecret = "B4657E03-D619";
            });

            var client = server.CreateClient();

            var request = new HttpRequestMessage(HttpMethod.Get, "/");
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", "token-1");

            // Act
            var response = await client.SendAsync(request);

            // Assert
            Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        }

        [Fact]
        public async Task InvalidAudienceCausesInvalidAuthentication() {
            // Arrange
            var server = CreateResourceServer(options => {
                options.Audience = "http://www.fabrikam.com/";
                options.ClientId = "Fabrikam";
                options.ClientSecret = "B4657E03-D619";
            });

            var client = server.CreateClient();

            var request = new HttpRequestMessage(HttpMethod.Get, "/");
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", "token-2");

            // Act
            var response = await client.SendAsync(request);

            // Assert
            Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        }

        [Fact]
        public async Task ValidAudienceAllowsSuccessfulAuthentication() {
            // Arrange
            var server = CreateResourceServer(options => {
                options.Audience = "http://www.fabrikam.com/";
                options.ClientId = "Fabrikam";
                options.ClientSecret = "B4657E03-D619";
            });

            var client = server.CreateClient();

            var request = new HttpRequestMessage(HttpMethod.Get, "/");
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", "token-3");

            // Act
            var response = await client.SendAsync(request);

            // Assert
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            Assert.Equal("Fabrikam", await response.Content.ReadAsStringAsync());
        }

        [Fact]
        public async Task ExpiredTicketCausesInvalidAuthentication() {
            // Arrange
            var server = CreateResourceServer(options => {
                options.ClientId = "Fabrikam";
                options.ClientSecret = "B4657E03-D619";
            });

            var client = server.CreateClient();

            var request = new HttpRequestMessage(HttpMethod.Get, "/");
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", "token-4");

            // Act and assert

            // Send a first request to persist the token in the memory cache.
            var response = await client.SendAsync(request);
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            Assert.Equal("Fabrikam", await response.Content.ReadAsStringAsync());

            // Wait 4 seconds to ensure
            // that the token is expired.
            await Task.Delay(4000);

            // Send a new request with the same access token.
            request = new HttpRequestMessage(HttpMethod.Get, "/");
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", "token-4");

            response = await client.SendAsync(request);
            Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        }

        private static TestServer CreateResourceServer(Action<OAuthIntrospectionOptions> configuration) {
            var server = CreateAuthorizationServer(options => { });

            var builder = new WebApplicationBuilder();

            builder.UseEnvironment("Testing");

            builder.ConfigureServices(services => {
                services.AddAuthentication();
                services.AddCaching();
            });

            builder.Configure(app => {
                app.UseOAuthIntrospection(options => {
                    options.AutomaticAuthenticate = true;
                    options.AutomaticChallenge = true;

                    options.Authority = server.BaseAddress.AbsoluteUri;
                    options.HttpClient = server.CreateClient();

                    // Run the configuration delegate
                    // registered by the unit tests.
                    configuration?.Invoke(options);
                });

                app.Run(context => {
                    if (!context.User.Identities.Any(identity => identity.IsAuthenticated)) {
                        return context.Authentication.ChallengeAsync();
                    }

                    return context.Response.WriteAsync(context.User.GetClaim(ClaimTypes.NameIdentifier));
                });
            });

            return new TestServer(builder);
        }

        private static TestServer CreateAuthorizationServer(Action<OpenIdConnectServerOptions> configuration) {
            var builder = new WebApplicationBuilder();

            builder.UseEnvironment("Testing");

            builder.ConfigureServices(services => {
                services.AddAuthentication();
                services.AddCaching();
                services.AddLogging();
            });

            builder.Configure(app => {
                var factory = app.ApplicationServices.GetRequiredService<ILoggerFactory>();
                factory.AddDebug();

                // Add a new OpenID Connect server instance.
                app.UseOpenIdConnectServer(options => {
                    options.Provider = new OpenIdConnectServerProvider {
                        // Implement ValidateClientAuthentication
                        // to bypass client authentication.
                        OnValidateClientAuthentication = context => {
                            if (string.IsNullOrEmpty(context.ClientId) ||
                                string.IsNullOrEmpty(context.ClientSecret)) {
                                context.Reject();

                                return Task.FromResult(0);
                            }

                            context.Skip();

                            return Task.FromResult(0);
                        },

                        // Implement DeserializeAccessToken to return an authentication ticket
                        // corresponding to the access token sent by the introspection middleware.
                        OnDeserializeAccessToken = context => {
                            // Skip the default logic when receiving the "invalid" token.
                            if (string.Equals(context.AccessToken, "invalid-token", StringComparison.Ordinal)) {
                                return Task.FromResult(0);
                            }

                            var identity = new ClaimsIdentity(context.Options.AuthenticationScheme);
                            identity.AddClaim(ClaimTypes.NameIdentifier, "Fabrikam");

                            var properties = new AuthenticationProperties {
                                IssuedUtc = context.Options.SystemClock.UtcNow - TimeSpan.FromDays(1),
                                ExpiresUtc = context.Options.SystemClock.UtcNow + TimeSpan.FromDays(1)
                            };

                            var ticket = new AuthenticationTicket(
                                new ClaimsPrincipal(identity),
                                properties, context.Options.AuthenticationScheme);

                            ticket.SetUsage(OpenIdConnectConstants.Usages.AccessToken);

                            switch (context.AccessToken) {
                                case "token-2": {
                                    ticket.SetAudiences("http://www.google.com/");

                                    break;
                                }

                                case "token-3": {
                                    ticket.SetAudiences("http://www.google.com/", "http://www.fabrikam.com/");

                                    break;
                                }

                                case "token-4": {
                                    ticket.Properties.ExpiresUtc = context.Options.SystemClock.UtcNow +
                                                                   TimeSpan.FromSeconds(2);

                                    break;
                                }
                            }

                            // Return a new authentication ticket containing the principal.
                            context.AuthenticationTicket = ticket;

                            return Task.FromResult(0);
                        }
                    };

                    // Run the configuration delegate
                    // registered by the unit tests.
                    configuration?.Invoke(options);
                });
            });

            return new TestServer(builder);
        }
    }
}
