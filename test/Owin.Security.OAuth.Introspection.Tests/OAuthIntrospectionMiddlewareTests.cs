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
using System.Reflection;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.AspNet.Testing.xunit;
using Microsoft.Owin.Security;
using Microsoft.Owin.Testing;
using Owin.Security.OpenIdConnect.Extensions;
using Owin.Security.OpenIdConnect.Server;
using Xunit;

namespace Owin.Security.OAuth.Introspection.Tests {
    public class OAuthIntrospectionMiddlewareTests {
        [ConditionalFact, FrameworkSkipCondition(RuntimeFrameworks.Mono)]
        public void MissingAuthorityThrowsAnException() {
            // Arrange, act, assert
            var exception = Assert.Throws<TargetInvocationException>(() => CreateResourceServer(options => {
                options.Authority = null;
            }));

            Assert.NotNull(exception.InnerException);
            Assert.IsType<ArgumentException>(exception.InnerException);
            Assert.StartsWith("The authority or the introspection endpoint must be configured.", exception.InnerException.Message);
        }

        [ConditionalFact, FrameworkSkipCondition(RuntimeFrameworks.Mono)]
        public void MissingCredentialsThrowAnException() {
            // Arrange, act, assert
            var exception = Assert.Throws<TargetInvocationException>(() => CreateResourceServer(options => {
                options.Authority = "http://www.fabrikam.com/";
            }));

            Assert.NotNull(exception.InnerException);
            Assert.IsType<ArgumentException>(exception.InnerException);
            Assert.StartsWith("Client credentials must be configured.", exception.InnerException.Message);
        }

        [ConditionalFact, FrameworkSkipCondition(RuntimeFrameworks.Mono)]
        public async Task MissingTokenCausesInvalidAuthentication() {
            // Arrange
            var server = CreateResourceServer(options => {
                options.ClientId = "Fabrikam";
                options.ClientSecret = "B4657E03-D619";
            });

            var client = server.HttpClient;

            var request = new HttpRequestMessage(HttpMethod.Get, "/");

            // Act
            var response = await client.SendAsync(request);

            // Assert
            Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        }

        [ConditionalFact, FrameworkSkipCondition(RuntimeFrameworks.Mono)]
        public async Task InvalidTokenCausesInvalidAuthentication() {
            // Arrange
            var server = CreateResourceServer(options => {
                options.ClientId = "Fabrikam";
                options.ClientSecret = "B4657E03-D619";
            });

            var client = server.HttpClient;

            var request = new HttpRequestMessage(HttpMethod.Get, "/");
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", "invalid-token");

            // Act
            var response = await client.SendAsync(request);

            // Assert
            Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        }

        [ConditionalFact, FrameworkSkipCondition(RuntimeFrameworks.Mono)]
        public async Task ValidTokenAllowsSuccessfulAuthentication() {
            // Arrange
            var server = CreateResourceServer(options => {
                options.ClientId = "Fabrikam";
                options.ClientSecret = "B4657E03-D619";
            });

            var client = server.HttpClient;

            var request = new HttpRequestMessage(HttpMethod.Get, "/");
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", "token-1");

            // Act
            var response = await client.SendAsync(request);

            // Assert
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            Assert.Equal("Fabrikam", await response.Content.ReadAsStringAsync());
        }

        [ConditionalFact, FrameworkSkipCondition(RuntimeFrameworks.Mono)]
        public async Task MissingAudienceCausesInvalidAuthentication() {
            // Arrange
            var server = CreateResourceServer(options => {
                options.Audiences.Add("http://www.fabrikam.com/");
                options.ClientId = "Fabrikam";
                options.ClientSecret = "B4657E03-D619";
            });

            var client = server.HttpClient;

            var request = new HttpRequestMessage(HttpMethod.Get, "/");
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", "token-1");

            // Act
            var response = await client.SendAsync(request);

            // Assert
            Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        }

        [ConditionalFact, FrameworkSkipCondition(RuntimeFrameworks.Mono)]
        public async Task InvalidAudienceCausesInvalidAuthentication() {
            // Arrange
            var server = CreateResourceServer(options => {
                options.Audiences.Add("http://www.fabrikam.com/");
                options.ClientId = "Fabrikam";
                options.ClientSecret = "B4657E03-D619";
            });

            var client = server.HttpClient;

            var request = new HttpRequestMessage(HttpMethod.Get, "/");
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", "token-2");

            // Act
            var response = await client.SendAsync(request);

            // Assert
            Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        }

        [ConditionalFact, FrameworkSkipCondition(RuntimeFrameworks.Mono)]
        public async Task ValidAudienceAllowsSuccessfulAuthentication() {
            // Arrange
            var server = CreateResourceServer(options => {
                options.Audiences.Add("http://www.fabrikam.com/");
                options.ClientId = "Fabrikam";
                options.ClientSecret = "B4657E03-D619";
            });

            var client = server.HttpClient;

            var request = new HttpRequestMessage(HttpMethod.Get, "/");
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", "token-3");

            // Act
            var response = await client.SendAsync(request);

            // Assert
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            Assert.Equal("Fabrikam", await response.Content.ReadAsStringAsync());
        }

        [ConditionalFact, FrameworkSkipCondition(RuntimeFrameworks.Mono)]
        public async Task AnyMatchingAudienceCausesSuccessfulAuthentication() {
            // Arrange
            var server = CreateResourceServer(options => {
                options.Audiences.Add("http://www.fabrikam.com/");
                options.Audiences.Add("http://www.google.com/");
                options.ClientId = "Fabrikam";
                options.ClientSecret = "B4657E03-D619";
                            });

            var client = server.HttpClient;

            var request = new HttpRequestMessage(HttpMethod.Get, "/");
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", "token-2");

            // Act
            var response = await client.SendAsync(request);

            // Assert
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            Assert.Equal("Fabrikam", await response.Content.ReadAsStringAsync());
        }

        [ConditionalFact, FrameworkSkipCondition(RuntimeFrameworks.Mono)]
        public async Task MultipleMatchingAudienceCausesSuccessfulAuthentication() {
            // Arrange
            var server = CreateResourceServer(options => {
                options.Audiences.Add("http://www.fabrikam.com/");
                options.Audiences.Add("http://www.google.com/");
                options.ClientId = "Fabrikam";
                options.ClientSecret = "B4657E03-D619";
            });

            var client = server.HttpClient;

            var request = new HttpRequestMessage(HttpMethod.Get, "/");
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", "token-3");

            // Act
            var response = await client.SendAsync(request);

            // Assert
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            Assert.Equal("Fabrikam", await response.Content.ReadAsStringAsync());
        }

        [ConditionalFact, FrameworkSkipCondition(RuntimeFrameworks.Mono)]
        public async Task ExpiredTicketCausesInvalidAuthentication() {
            // Arrange
            var server = CreateResourceServer(options => {
                options.ClientId = "Fabrikam";
                options.ClientSecret = "B4657E03-D619";
            });

            var client = server.HttpClient;

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

            return TestServer.Create(app => {
                app.UseOAuthIntrospection(options => {
                    options.AuthenticationMode = AuthenticationMode.Active;

                    options.Authority = server.BaseAddress.AbsoluteUri;
                    options.HttpClient = server.HttpClient;

                    // Run the configuration delegate
                    // registered by the unit tests.
                    configuration?.Invoke(options);
                });

                app.Run(context => {
                    if (context.Authentication.User == null ||
                       !context.Authentication.User.Identities.Any(identity => identity.IsAuthenticated)) {
                        context.Authentication.Challenge();

                        return Task.FromResult(0);
                    }

                    return context.Response.WriteAsync(context.Authentication.User.GetClaim(ClaimTypes.NameIdentifier));
                });
            });
        }

        private static TestServer CreateAuthorizationServer(Action<OpenIdConnectServerOptions> configuration) {
            return TestServer.Create(app => {
                // Add a new OpenID Connect server instance.
                app.UseOpenIdConnectServer(options => {
                    options.AllowInsecureHttp = true;

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

                            var identity = new ClaimsIdentity(context.Options.AuthenticationType);
                            identity.AddClaim(ClaimTypes.NameIdentifier, "Fabrikam");

                            var properties = new AuthenticationProperties {
                                IssuedUtc = context.Options.SystemClock.UtcNow - TimeSpan.FromDays(1),
                                ExpiresUtc = context.Options.SystemClock.UtcNow + TimeSpan.FromDays(1)
                            };

                            var ticket = new AuthenticationTicket(identity, properties);

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
                                    ticket.Properties.ExpiresUtc = context.Options.SystemClock.UtcNow + TimeSpan.FromSeconds(2);

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
        }
    }
}
