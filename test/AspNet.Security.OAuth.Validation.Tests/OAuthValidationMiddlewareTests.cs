﻿/*
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
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Authentication;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Moq;
using Xunit;

namespace AspNet.Security.OAuth.Validation.Tests {
    public class OAuthValidationMiddlewareTests {
        [Fact]
        public async Task InvalidTokenCausesInvalidAuthentication() {
            // Arrange
            var server = CreateResourceServer();

            var client = server.CreateClient();

            var request = new HttpRequestMessage(HttpMethod.Get, "/");
            request.Headers.Authorization = new AuthenticationHeaderValue(OAuthValidationDefaults.AuthenticationScheme, "invalid-token");

            // Act
            var response = await client.SendAsync(request);

            // Assert
            Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        }

        [Fact]
        public async Task ValidTokenAllowsSuccessfulAuthentication() {
            // Arrange
            var server = CreateResourceServer();

            var client = server.CreateClient();

            var request = new HttpRequestMessage(HttpMethod.Get, "/");
            request.Headers.Authorization = new AuthenticationHeaderValue(OAuthValidationDefaults.AuthenticationScheme, "token-1");

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

            var client = server.CreateClient();

            var request = new HttpRequestMessage(HttpMethod.Get, "/");
            request.Headers.Authorization = new AuthenticationHeaderValue(OAuthValidationDefaults.AuthenticationScheme, "token-1");

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

            var client = server.CreateClient();

            var request = new HttpRequestMessage(HttpMethod.Get, "/");
            request.Headers.Authorization = new AuthenticationHeaderValue(OAuthValidationDefaults.AuthenticationScheme, "token-2");

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

            var client = server.CreateClient();

            var request = new HttpRequestMessage(HttpMethod.Get, "/");
            request.Headers.Authorization = new AuthenticationHeaderValue(OAuthValidationDefaults.AuthenticationScheme, "token-3");

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
                options.Audiences.Add("http://www.unknown.com/");
                options.Audiences.Add("http://www.google.com/");
            });

            var client = server.CreateClient();

            var request = new HttpRequestMessage(HttpMethod.Get, "/");
            request.Headers.Authorization = new AuthenticationHeaderValue(OAuthValidationDefaults.AuthenticationScheme, "token-2");

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

            var client = server.CreateClient();

            var request = new HttpRequestMessage(HttpMethod.Get, "/");
            request.Headers.Authorization = new AuthenticationHeaderValue(OAuthValidationDefaults.AuthenticationScheme, "token-3");

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

            var client = server.CreateClient();

            var request = new HttpRequestMessage(HttpMethod.Get, "/");
            request.Headers.Authorization = new AuthenticationHeaderValue(OAuthValidationDefaults.AuthenticationScheme, "token-4");

            // Act
            var response = await client.SendAsync(request);

            // Assert
            Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        }

        private static TestServer CreateResourceServer(Action<OAuthValidationOptions> configuration = null) {
            var builder = new WebHostBuilder();

            var format = new Mock<ISecureDataFormat<AuthenticationTicket>>();

            format.Setup(mock => mock.Unprotect(It.Is<string>(token => token == "invalid-token")))
                  .Returns(value: null);

            format.Setup(mock => mock.Unprotect(It.Is<string>(token => token == "token-1")))
                  .Returns(delegate {
                      var identity = new ClaimsIdentity(OAuthValidationDefaults.AuthenticationScheme);
                      identity.AddClaim(new Claim(ClaimTypes.NameIdentifier, "Fabrikam"));

                      var properties = new AuthenticationProperties();

                      return new AuthenticationTicket(new ClaimsPrincipal(identity),
                          properties, OAuthValidationDefaults.AuthenticationScheme);
                  });

            format.Setup(mock => mock.Unprotect(It.Is<string>(token => token == "token-2")))
                  .Returns(delegate {
                      var identity = new ClaimsIdentity(OAuthValidationDefaults.AuthenticationScheme);
                      identity.AddClaim(new Claim(ClaimTypes.NameIdentifier, "Fabrikam"));

                      var properties = new AuthenticationProperties(new Dictionary<string, string> {
                          [OAuthValidationConstants.Properties.Audiences] = "http://www.google.com/"
                      });

                      return new AuthenticationTicket(new ClaimsPrincipal(identity),
                          properties, OAuthValidationDefaults.AuthenticationScheme);
                  });

            format.Setup(mock => mock.Unprotect(It.Is<string>(token => token == "token-3")))
                  .Returns(delegate {
                      var identity = new ClaimsIdentity(OAuthValidationDefaults.AuthenticationScheme);
                      identity.AddClaim(new Claim(ClaimTypes.NameIdentifier, "Fabrikam"));

                      var properties = new AuthenticationProperties(new Dictionary<string, string> {
                          [OAuthValidationConstants.Properties.Audiences] = "http://www.google.com/ http://www.fabrikam.com/"
                      });

                      return new AuthenticationTicket(new ClaimsPrincipal(identity),
                          properties, OAuthValidationDefaults.AuthenticationScheme);
                  });

            format.Setup(mock => mock.Unprotect(It.Is<string>(token => token == "token-4")))
                  .Returns(delegate {
                      var identity = new ClaimsIdentity(OAuthValidationDefaults.AuthenticationScheme);
                      identity.AddClaim(new Claim(ClaimTypes.NameIdentifier, "Fabrikam"));

                      var properties = new AuthenticationProperties();
                      properties.ExpiresUtc = DateTimeOffset.UtcNow - TimeSpan.FromDays(1);

                      return new AuthenticationTicket(new ClaimsPrincipal(identity),
                          properties, OAuthValidationDefaults.AuthenticationScheme);
                  });

            builder.UseEnvironment("Testing");

            builder.ConfigureServices(services => {
                services.AddAuthentication();
            });

            builder.Configure(app => {
                app.UseOAuthValidation(options => {
                    options.AutomaticAuthenticate = true;
                    options.AutomaticChallenge = true;
                    options.TicketFormat = format.Object;

                    // Run the configuration delegate
                    // registered by the unit tests.
                    configuration?.Invoke(options);
                });

                app.Run(context => {
                    if (!context.User.Identities.Any(identity => identity.IsAuthenticated)) {
                        return context.Authentication.ChallengeAsync();
                    }

                    var identifier = context.User.FindFirst(ClaimTypes.NameIdentifier).Value;
                    return context.Response.WriteAsync(identifier);
                });
            });

            return new TestServer(builder);
        }
    }
}
