/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/aspnet-contrib/AspNet.Security.OAuth.Extensions for more information
 * concerning the license and the contributors participating to this project.
 */

using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.Owin.Security;
using Microsoft.Owin.Testing;
using Moq;
using Xunit;

namespace Owin.Security.OAuth.Validation.Tests {
    public class OAuthValidationMiddlewareTests {
        [Fact]
        public async Task InvalidTokenCausesInvalidAuthentication() {
            // Arrange
            var server = CreateResourceServer();

            var client = server.HttpClient;

            var request = new HttpRequestMessage(HttpMethod.Get, "/");
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", Tokens.Invalid);

            // Act
            var response = await client.SendAsync(request);

            // Assert
            Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        }

        [Fact]
        public async Task ValidTokenAllowsSuccessfulAuthentication() {
            // Arrange
            var server = CreateResourceServer();

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
        public async Task MissingAudienceCausesInvalidAuthentication() {
            // Arrange
            var server = CreateResourceServer(options => {
                options.Audiences.Add("http://www.fabrikam.com/");
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
        public async Task InvalidAudienceCausesInvalidAuthentication() {
            // Arrange
            var server = CreateResourceServer(options => {
                options.Audiences.Add("http://www.fabrikam.com/");
            });

            var client = server.HttpClient;

            var request = new HttpRequestMessage(HttpMethod.Get, "/");
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", Tokens.SingleAudience);

            // Act
            var response = await client.SendAsync(request);

            // Assert
            Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        }

        [Fact]
        public async Task ValidAudienceAllowsSuccessfulAuthentication() {
            // Arrange
            var server = CreateResourceServer(options => {
                options.Audiences.Add("http://www.fabrikam.com/");
            });

            var client = server.HttpClient;

            var request = new HttpRequestMessage(HttpMethod.Get, "/");
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", Tokens.MultipleAudiences);

            // Act
            var response = await client.SendAsync(request);

            // Assert
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            Assert.Equal("Fabrikam", await response.Content.ReadAsStringAsync());
        }

        [Fact]
        public async Task AnyMatchingAudienceCausesSuccessfulAuthentication() {
            // Arrange
            var server = CreateResourceServer(options => {
                options.Audiences.Add("http://www.fabrikam.com/");
                options.Audiences.Add("http://www.google.com/");
            });

            var client = server.HttpClient;

            var request = new HttpRequestMessage(HttpMethod.Get, "/");
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", Tokens.SingleAudience);

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
            });

            var client = server.HttpClient;

            var request = new HttpRequestMessage(HttpMethod.Get, "/");
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", Tokens.MultipleAudiences);

            // Act
            var response = await client.SendAsync(request);

            // Assert
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            Assert.Equal("Fabrikam", await response.Content.ReadAsStringAsync());
        }

        [Fact]
        public async Task ExpiredTicketCausesInvalidAuthentication() {
            // Arrange
            var server = CreateResourceServer();

            var client = server.HttpClient;

            var request = new HttpRequestMessage(HttpMethod.Get, "/");
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", Tokens.Expired);

            // Act
            var response = await client.SendAsync(request);

            // Assert
            Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        }

        [Fact]
        public async Task TokenSetToNullDuringParseAccessTokenEventCausesInvalidAuthentication() {
            // Arrange
            var server = CreateResourceServer(options => {
                options.Events = new OAuthValidationEvents {
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
        public async Task TokenSetToInvalidValueDuringParseAccessTokenEventCausesInvalidAuthentication() {
            // Arrange
            var server = CreateResourceServer(options => {
                options.Events = new OAuthValidationEvents {
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
        public async Task TokenSetToValidValueDuringParseAccessTokenEventAllowsSuccessfulAuthentication() {
            // Arrange
            var server = CreateResourceServer(options => {
                options.Events = new OAuthValidationEvents {
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
                options.Events = new OAuthValidationEvents {
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
                options.Events = new OAuthValidationEvents {
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

        private static TestServer CreateResourceServer(Action<OAuthValidationOptions> configuration = null) {
            var format = new Mock<ISecureDataFormat<AuthenticationTicket>>();

            format.Setup(mock => mock.Unprotect(It.Is<string>(token => token == Tokens.Invalid)))
                  .Returns(value: null);

            format.Setup(mock => mock.Unprotect(It.Is<string>(token => token == Tokens.Valid)))
                  .Returns(delegate {
                      var identity = new ClaimsIdentity(OAuthValidationDefaults.AuthenticationScheme);
                      identity.AddClaim(new Claim(ClaimTypes.NameIdentifier, "Fabrikam"));

                      return new AuthenticationTicket(identity, new AuthenticationProperties());
                  });

            format.Setup(mock => mock.Unprotect(It.Is<string>(token => token == Tokens.SingleAudience)))
                  .Returns(delegate {
                      var identity = new ClaimsIdentity(OAuthValidationDefaults.AuthenticationScheme);
                      identity.AddClaim(new Claim(ClaimTypes.NameIdentifier, "Fabrikam"));

                      var properties = new AuthenticationProperties(new Dictionary<string, string> {
                          [OAuthValidationConstants.Properties.Audiences] = "http://www.google.com/"
                      });

                      return new AuthenticationTicket(identity, properties);
                  });

            format.Setup(mock => mock.Unprotect(It.Is<string>(token => token == Tokens.MultipleAudiences)))
                  .Returns(delegate {
                      var identity = new ClaimsIdentity(OAuthValidationDefaults.AuthenticationScheme);
                      identity.AddClaim(new Claim(ClaimTypes.NameIdentifier, "Fabrikam"));

                      var properties = new AuthenticationProperties(new Dictionary<string, string> {
                          [OAuthValidationConstants.Properties.Audiences] = "http://www.google.com/ http://www.fabrikam.com/"
                      });

                      return new AuthenticationTicket(identity, properties);
                  });

            format.Setup(mock => mock.Unprotect(It.Is<string>(token => token == Tokens.Expired)))
                  .Returns(delegate {
                      var identity = new ClaimsIdentity(OAuthValidationDefaults.AuthenticationScheme);
                      identity.AddClaim(new Claim(ClaimTypes.NameIdentifier, "Fabrikam"));

                      var properties = new AuthenticationProperties();
                      properties.ExpiresUtc = DateTimeOffset.UtcNow - TimeSpan.FromDays(1);

                      return new AuthenticationTicket(identity, properties);
                  });

            return TestServer.Create(app => {
                app.UseOAuthValidation(options => {
                    options.AuthenticationMode = AuthenticationMode.Active;
                    options.AccessTokenFormat = format.Object;

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

                    var identifier = context.Authentication.User.FindFirst(ClaimTypes.NameIdentifier).Value;
                    return context.Response.WriteAsync(identifier);
                });
            });
        }
    }
}
