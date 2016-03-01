/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/aspnet-contrib/AspNet.Security.OAuth.Extensions for more information
 * concerning the license and the contributors participating to this project.
 */

using System;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Reflection;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.Owin.Security;
using Microsoft.Owin.Testing;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using Xunit;

namespace Owin.Security.OAuth.Introspection.Tests {
    public class OAuthIntrospectionMiddlewareTests {
        [Fact]
        public void MissingAuthorityThrowsAnException() {
            // Arrange, act, assert
            var exception = Assert.Throws<TargetInvocationException>(() => CreateResourceServer(options => {
                options.Authority = null;
            }));

            Assert.NotNull(exception.InnerException);
            Assert.IsType<ArgumentException>(exception.InnerException);
            Assert.StartsWith("The authority or the introspection endpoint must be configured.", exception.InnerException.Message);
        }

        [Fact]
        public void MissingCredentialsThrowAnException() {
            // Arrange, act, assert
            var exception = Assert.Throws<TargetInvocationException>(() => CreateResourceServer(options => {
                options.Authority = "http://www.fabrikam.com/";
            }));

            Assert.NotNull(exception.InnerException);
            Assert.IsType<ArgumentException>(exception.InnerException);
            Assert.StartsWith("Client credentials must be configured.", exception.InnerException.Message);
        }

        [Fact]
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

        [Fact]
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

        [Fact]
        public async Task ValidTokenAllowsSuccessfulAuthentication() {
            // Arrange
            var server = CreateResourceServer(options => {
                options.ClientId = "Fabrikam";
                options.ClientSecret = "B4657E03-D619";
            });

            var client = server.HttpClient;

            var request = new HttpRequestMessage(HttpMethod.Get, "/");
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", "valid-token");

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
                options.Audiences.Add("http://www.fabrikam.com/");
                options.ClientId = "Fabrikam";
                options.ClientSecret = "B4657E03-D619";
            });

            var client = server.HttpClient;

            var request = new HttpRequestMessage(HttpMethod.Get, "/");
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", "valid-token");

            // Act
            var response = await client.SendAsync(request);

            // Assert
            Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        }

        [Fact]
        public async Task InvalidAudienceCausesInvalidAuthentication() {
            // Arrange
            var server = CreateResourceServer(options => {
                options.Audiences.Add("http://www.fabrikam.com/");
                options.ClientId = "Fabrikam";
                options.ClientSecret = "B4657E03-D619";
            });

            var client = server.HttpClient;

            var request = new HttpRequestMessage(HttpMethod.Get, "/");
            request.Headers.Authorization = new AuthenticationHeaderValue(
                "Bearer", "valid-token-with-single-audience");

            // Act
            var response = await client.SendAsync(request);

            // Assert
            Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        }

        [Fact]
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
            request.Headers.Authorization = new AuthenticationHeaderValue(
                "Bearer", "valid-token-with-single-audience");

            // Act
            var response = await client.SendAsync(request);

            // Assert
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            Assert.Equal("Fabrikam", await response.Content.ReadAsStringAsync());
        }

        [Fact]
        public async Task ValidAudienceAllowsSuccessfulAuthentication() {
            // Arrange
            var server = CreateResourceServer(options => {
                options.Audiences.Add("http://www.fabrikam.com/");
                options.ClientId = "Fabrikam";
                options.ClientSecret = "B4657E03-D619";
            });

            var client = server.HttpClient;

            var request = new HttpRequestMessage(HttpMethod.Get, "/");
            request.Headers.Authorization = new AuthenticationHeaderValue(
                "Bearer", "valid-token-with-multiple-audiences");

            // Act
            var response = await client.SendAsync(request);

            // Assert
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            Assert.Equal("Fabrikam", await response.Content.ReadAsStringAsync());
        }

        [Fact]
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
            request.Headers.Authorization = new AuthenticationHeaderValue(
                "Bearer", "valid-token-with-multiple-audiences");

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

            var client = server.HttpClient;

            var request = new HttpRequestMessage(HttpMethod.Get, "/");
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", "expired-token");

            // Act
            var response = await client.SendAsync(request);

            // Assert
            Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        }

        [Fact]
        public async Task TokenSetToNullDuringParseAccessTokenEventCausesInvalidAuthentication() {
            // Arrange
            var server = CreateResourceServer(options => {
                options.ClientId = "Fabrikam";
                options.ClientSecret = "B4657E03-D619";
                options.Events = new OAuthIntrospectionEvents {
                    OnParseAccessToken = context => {
                        context.Token = null;
                        return Task.FromResult(0);
                    }
                };
            });

            var client = server.HttpClient;

            var request = new HttpRequestMessage(HttpMethod.Get, "/");
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", Tokens.Valid);

            // Act
            var response = await client.SendAsync(request);

            // Assert
            Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        }

        [Fact]
        public async Task TokenSetToInvalidTokenDuringParseAccessTokenEventCausesInvalidAuthentication() {
            // Arrange
            var server = CreateResourceServer(options => {
                options.ClientId = "Fabrikam";
                options.ClientSecret = "B4657E03-D619";
                options.Events = new OAuthIntrospectionEvents {
                    OnParseAccessToken = context => {
                        context.Token = Tokens.Invalid;
                        return Task.FromResult(0);
                    }
                };
            });

            var client = server.HttpClient;

            var request = new HttpRequestMessage(HttpMethod.Get, "/");
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", Tokens.Valid);

            // Act
            var response = await client.SendAsync(request);

            // Assert
            Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        }

        [Fact]
        public async Task TokenSetToValidTokenDuringParseAccessTokenEventAllowsSuccessfulAuthentication() {
            // Arrange
            var server = CreateResourceServer(options => {
                options.ClientId = "Fabrikam";
                options.ClientSecret = "B4657E03-D619";
                options.Events = new OAuthIntrospectionEvents {
                    OnParseAccessToken = context => {
                        context.Token = Tokens.Valid;
                        return Task.FromResult(0);
                    }
                };
            });

            var client = server.HttpClient;

            var request = new HttpRequestMessage(HttpMethod.Get, "/");
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", Tokens.Invalid);

            // Act
            var response = await client.SendAsync(request);

            // Assert
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            Assert.Equal("Fabrikam", await response.Content.ReadAsStringAsync());
        }

        [Fact]
        public async Task TokenValidatedEventSettingIsValidAsTrueCausesSuccessfulAuthentication() {
            // Arrange
            var server = CreateResourceServer(options => {
                options.ClientId = "Fabrikam";
                options.ClientSecret = "B4657E03-D619";
                options.Events = new OAuthIntrospectionEvents {
                    OnValidateToken = context => {
                        context.IsValid = true;
                        return Task.FromResult(0);
                    }
                };
            });

            var client = server.HttpClient;

            var request = new HttpRequestMessage(HttpMethod.Get, "/");
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", Tokens.Valid);

            // Act
            var response = await client.SendAsync(request);

            // Assert
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            Assert.Equal("Fabrikam", await response.Content.ReadAsStringAsync());
        }

        [Fact]
        public async Task TokenValidatedEventSettingIsValidAsFalseCausesInvalidAuthentication() {
            // Arrange
            var server = CreateResourceServer(options => {
                options.ClientId = "Fabrikam";
                options.ClientSecret = "B4657E03-D619";
                options.Events = new OAuthIntrospectionEvents {
                    OnValidateToken = context => {
                        context.IsValid = false;
                        return Task.FromResult(0);
                    }
                };
            });

            var client = server.HttpClient;

            var request = new HttpRequestMessage(HttpMethod.Get, "/");
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", Tokens.Valid);

            // Act
            var response = await client.SendAsync(request);

            // Assert
            Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        }

        private static class Tokens {
            public const string Invalid = "invalid-token";
            public const string Valid = "valid-token";
            public const string SingleAudience = "valid-token-with-single-audience";
            public const string MultipleAudiences = "valid-token-with-multiple-audiences";
            public const string Expired = "expired-token";
        }

        private static TestServer CreateResourceServer(Action<OAuthIntrospectionOptions> configuration) {
            var server = CreateAuthorizationServer();

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

                    return context.Response.WriteAsync(context.Authentication.User.FindFirst(ClaimTypes.NameIdentifier)?.Value);
                });
            });
        }

        private static TestServer CreateAuthorizationServer() {
            return TestServer.Create(app => {
                app.Map("/.well-known/openid-configuration", map => map.Run(async context => {
                    using (var buffer = new MemoryStream())
                    using (var writer = new JsonTextWriter(new StreamWriter(buffer))) {
                        var payload = new JObject {
                            [OAuthIntrospectionConstants.Metadata.IntrospectionEndpoint] = "http://localhost/connect/introspect"
                        };

                        payload.WriteTo(writer);
                        writer.Flush();

                        context.Response.ContentLength = buffer.Length;
                        context.Response.ContentType = "application/json;charset=UTF-8";

                        buffer.Seek(offset: 0, loc: SeekOrigin.Begin);
                        await buffer.CopyToAsync(context.Response.Body, 4096, context.Request.CallCancelled);
                    }
                }));

                app.Map("/connect/introspect", map => map.Run(async context => {
                    using (var buffer = new MemoryStream())
                    using (var writer = new JsonTextWriter(new StreamWriter(buffer))) {
                        var payload = new JObject();
                        var form = await context.Request.ReadFormAsync();

                        switch (form[OAuthIntrospectionConstants.Parameters.Token]) {
                            case Tokens.Invalid: {
                                payload[OAuthIntrospectionConstants.Claims.Active] = false;

                                break;
                            }

                            case Tokens.Expired: {
                                payload[OAuthIntrospectionConstants.Claims.Active] = true;
                                payload[OAuthIntrospectionConstants.Claims.Subject] = "Fabrikam";

                                // 1451602800 = 01/01/2016 - 00:00:00 AM.
                                payload[OAuthIntrospectionConstants.Claims.ExpiresAt] = 1455359642;

                                break;
                            }

                            case Tokens.Valid: {
                                payload[OAuthIntrospectionConstants.Claims.Active] = true;
                                payload[OAuthIntrospectionConstants.Claims.Subject] = "Fabrikam";

                                break;
                            }

                            case Tokens.SingleAudience: {
                                payload[OAuthIntrospectionConstants.Claims.Active] = true;
                                payload[OAuthIntrospectionConstants.Claims.Subject] = "Fabrikam";
                                payload[OAuthIntrospectionConstants.Claims.Audience] = "http://www.google.com/";

                                break;
                            }

                            case Tokens.MultipleAudiences: {
                                payload[OAuthIntrospectionConstants.Claims.Active] = true;
                                payload[OAuthIntrospectionConstants.Claims.Subject] = "Fabrikam";
                                payload[OAuthIntrospectionConstants.Claims.Audience] = JArray.FromObject(new[] {
                                    "http://www.google.com/", "http://www.fabrikam.com/"
                                });

                                break;
                            }
                        }

                        payload.WriteTo(writer);
                        writer.Flush();

                        context.Response.ContentLength = buffer.Length;
                        context.Response.ContentType = "application/json;charset=UTF-8";

                        buffer.Seek(offset: 0, loc: SeekOrigin.Begin);
                        await buffer.CopyToAsync(context.Response.Body, 4096, context.Request.CallCancelled);
                    }
                }));
            });
        }
    }
}
