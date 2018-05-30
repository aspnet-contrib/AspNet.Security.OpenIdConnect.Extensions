/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/aspnet-contrib/AspNet.Security.OAuth.Extensions for more information
 * concerning the license and the contributors participating to this project.
 */

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.Logging;
using Microsoft.Owin.Security;
using Microsoft.Owin.Testing;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using Xunit;

namespace Owin.Security.OAuth.Introspection.Tests
{
    public class OAuthIntrospectionHandlerTests
    {
        [Fact]
        public async Task AuthenticateCoreAsync_MissingTokenCausesInvalidAuthentication()
        {
            // Arrange
            var server = CreateResourceServer();
            var client = server.HttpClient;

            var request = new HttpRequestMessage(HttpMethod.Get, "/");

            // Act
            var response = await client.SendAsync(request);

            // Assert
            Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        }

        [Fact]
        public async Task AuthenticateCoreAsync_InvalidTokenCausesInvalidAuthentication()
        {
            // Arrange
            var server = CreateResourceServer();
            var client = server.HttpClient;

            var request = new HttpRequestMessage(HttpMethod.Get, "/");
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", "invalid-token");

            // Act
            var response = await client.SendAsync(request);

            // Assert
            Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        }

        [Fact]
        public async Task AuthenticateCoreAsync_ValidTokenAllowsSuccessfulAuthentication()
        {
            // Arrange
            var server = CreateResourceServer();
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
        public async Task AuthenticateCoreAsync_MissingTokenUsageAllowsSuccessfulAuthentication()
        {
            // Arrange
            var server = CreateResourceServer();
            var client = server.HttpClient;

            var request = new HttpRequestMessage(HttpMethod.Get, "/");
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", "valid-token-without-usage");

            // Act
            var response = await client.SendAsync(request);

            // Assert
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            Assert.Equal("Fabrikam", await response.Content.ReadAsStringAsync());
        }

        [Fact]
        public async Task AuthenticateCoreAsync_InvalidTokenUsageCausesInvalidAuthentication()
        {
            // Arrange
            var server = CreateResourceServer();
            var client = server.HttpClient;

            var request = new HttpRequestMessage(HttpMethod.Get, "/");
            request.Headers.Authorization = new AuthenticationHeaderValue(
                "Bearer", "valid-token-with-invalid-usage");

            // Act
            var response = await client.SendAsync(request);

            // Assert
            Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        }

        [Fact]
        public async Task AuthenticateCoreAsync_ValidTokenUsageAllowsSuccessfulAuthentication()
        {
            // Arrange
            var server = CreateResourceServer();
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
        public async Task AuthenticateCoreAsync_ExpiredTicketCausesInvalidAuthentication()
        {
            // Arrange
            var server = CreateResourceServer();
            var client = server.HttpClient;

            var request = new HttpRequestMessage(HttpMethod.Get, "/");
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", "expired-token");

            // Act
            var response = await client.SendAsync(request);

            // Assert
            Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        }

        [Fact]
        public async Task AuthenticateCoreAsync_MissingAudienceCausesInvalidAuthentication()
        {
            // Arrange
            var server = CreateResourceServer(options =>
            {
                options.Audiences.Add("http://www.fabrikam.com/");
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
        public async Task AuthenticateCoreAsync_InvalidAudienceCausesInvalidAuthentication()
        {
            // Arrange
            var server = CreateResourceServer(options =>
            {
                options.Audiences.Add("http://www.fabrikam.com/");
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
        public async Task AuthenticateCoreAsync_AnyMatchingAudienceCausesSuccessfulAuthentication()
        {
            // Arrange
            var server = CreateResourceServer(options =>
            {
                options.Audiences.Add("http://www.contoso.com/");
                options.Audiences.Add("http://www.fabrikam.com/");
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
        public async Task AuthenticateCoreAsync_ValidAudienceAllowsSuccessfulAuthentication()
        {
            // Arrange
            var server = CreateResourceServer(options =>
            {
                options.Audiences.Add("http://www.fabrikam.com/");
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
        public async Task AuthenticateCoreAsync_MultipleMatchingAudienceCausesSuccessfulAuthentication()
        {
            // Arrange
            var server = CreateResourceServer(options =>
            {
                options.Audiences.Add("http://www.fabrikam.com/");
                options.Audiences.Add("http://www.google.com/");
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
        public async Task AuthenticateCoreAsync_AuthenticationTicketContainsRequiredClaims()
        {
            // Arrange
            var server = CreateResourceServer();
            var client = server.HttpClient;

            var request = new HttpRequestMessage(HttpMethod.Get, "/ticket");
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", "valid-token-with-scopes");

            // Act
            var response = await client.SendAsync(request);

            var ticket = JObject.Parse(await response.Content.ReadAsStringAsync());
            var claims = ticket.Value<JArray>("Claims").Select(claim => new
            {
                Type = claim.Value<string>(nameof(Claim.Type)),
                Value = claim.Value<string>(nameof(Claim.Value))
            });

            // Assert
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            Assert.Contains(new { Type = OAuthIntrospectionConstants.Claims.Subject, Value = "Fabrikam" }, claims);
            Assert.Contains(new { Type = OAuthIntrospectionConstants.Claims.Scope, Value = "openid" }, claims);
            Assert.Contains(new { Type = OAuthIntrospectionConstants.Claims.Scope, Value = "profile" }, claims);
        }

        [Fact]
        public async Task AuthenticateCoreAsync_AuthenticationTicketContainsRequiredProperties()
        {
            // Arrange
            var server = CreateResourceServer(options =>
            {
                options.SaveToken = true;
            });

            var client = server.HttpClient;

            var request = new HttpRequestMessage(HttpMethod.Get, "/ticket");
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", "valid-token");

            // Act
            var response = await client.SendAsync(request);

            var ticket = JObject.Parse(await response.Content.ReadAsStringAsync());
            var properties = from claim in ticket.Value<JArray>("Properties")
                             select new
                             {
                                 Name = claim.Value<string>("Name"),
                                 Value = claim.Value<string>("Value")
                             };

            // Assert
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);

            Assert.Contains(properties, property => property.Name == "access_token" &&
                                                    property.Value == "valid-token");
        }

        [Fact]
        public async Task AuthenticateCoreAsync_InvalidReplacedTokenCausesInvalidAuthentication()
        {
            // Arrange
            var server = CreateResourceServer(options =>
            {
                options.Events.OnRetrieveToken = context =>
                {
                    context.Token = "invalid-token";

                    return Task.CompletedTask;
                };
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
        public async Task AuthenticateCoreAsync_ValidReplacedTokenCausesSuccessfulAuthentication()
        {
            // Arrange
            var server = CreateResourceServer(options =>
            {
                options.Events.OnRetrieveToken = context =>
                {
                    context.Token = "valid-token";

                    return Task.CompletedTask;
                };
            });

            var client = server.HttpClient;

            var request = new HttpRequestMessage(HttpMethod.Get, "/");
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", "invalid-token");

            // Act
            var response = await client.SendAsync(request);

            // Assert
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            Assert.Equal("Fabrikam", await response.Content.ReadAsStringAsync());
        }

        [Fact]
        public async Task AuthenticateCoreAsync_NullTicketAndHandleValidationFromReceiveTokenCauseInvalidAuthentication()
        {
            // Arrange
            var server = CreateResourceServer(options =>
            {
                options.Events.OnRetrieveToken = context =>
                {
                    context.Ticket = null;
                    context.HandleValidation();

                    return Task.CompletedTask;
                };
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
        public async Task AuthenticateCoreAsync_ReplacedTicketAndHandleValidationFromReceiveTokenCauseSuccessfulAuthentication()
        {
            // Arrange
            var server = CreateResourceServer(options =>
            {
                options.Events.OnRetrieveToken = context =>
                {
                    var identity = new ClaimsIdentity(context.Options.AuthenticationType);
                    identity.AddClaim(new Claim(OAuthIntrospectionConstants.Claims.Subject, "Fabrikam"));

                    context.Ticket = new AuthenticationTicket(identity, new AuthenticationProperties());
                    context.HandleValidation();

                    return Task.CompletedTask;
                };
            });

            var client = server.HttpClient;

            var request = new HttpRequestMessage(HttpMethod.Get, "/");
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", "invalid-token");

            // Act
            var response = await client.SendAsync(request);

            // Assert
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            Assert.Equal("Fabrikam", await response.Content.ReadAsStringAsync());
        }

        [Fact]
        public async Task AuthenticateCoreAsync_NullTicketFromValidateTokenCauseInvalidAuthentication()
        {
            // Arrange
            var server = CreateResourceServer(options =>
            {
                options.Events.OnValidateToken = context =>
                {
                    context.Ticket = null;

                    return Task.CompletedTask;
                };
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
        public async Task AuthenticateCoreAsync_UpdatedTicketFromValidateTokenCausesSuccessfulAuthentication()
        {
            // Arrange
            var server = CreateResourceServer(options =>
            {
                options.Events.OnValidateToken = context =>
                {
                    var identity = new ClaimsIdentity(context.Options.AuthenticationType);
                    identity.AddClaim(new Claim(OAuthIntrospectionConstants.Claims.Subject, "Contoso"));

                    context.Ticket = new AuthenticationTicket(identity, new AuthenticationProperties());

                    return Task.CompletedTask;
                };
            });

            var client = server.HttpClient;

            var request = new HttpRequestMessage(HttpMethod.Get, "/");
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", "valid-token");

            // Act
            var response = await client.SendAsync(request);

            // Assert
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            Assert.Equal("Contoso", await response.Content.ReadAsStringAsync());
        }

        [Fact]
        public async Task HandleUnauthorizedAsync_ErrorDetailsAreResolvedFromChallengeContext()
        {
            // Arrange
            var server = CreateResourceServer(options =>
            {
                options.IncludeErrorDetails = false;
                options.Realm = "global_realm";

                options.Events.OnApplyChallenge = context =>
                {
                    // Assert
                    Assert.Equal("custom_error", context.Error);
                    Assert.Equal("custom_error_description", context.ErrorDescription);
                    Assert.Equal("custom_error_uri", context.ErrorUri);
                    Assert.Equal("custom_realm", context.Realm);
                    Assert.Equal("custom_scope", context.Scope);

                    return Task.CompletedTask;
                };
            });

            var client = server.HttpClient;

            // Act
            var response = await client.GetAsync("/challenge");

            // Assert
            Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
            Assert.Equal(@"Bearer realm=""custom_realm"", error=""custom_error"", error_description=""custom_error_description"", " +
                         @"error_uri=""custom_error_uri"", scope=""custom_scope""", response.Headers.WwwAuthenticate.ToString());
        }

        [Theory]
        [InlineData("invalid-token", OAuthIntrospectionConstants.Errors.InvalidToken, "The access token is not valid.")]
        [InlineData("expired-token", OAuthIntrospectionConstants.Errors.InvalidToken, "The access token is no longer valid.")]
        public async Task HandleUnauthorizedAsync_ErrorDetailsAreInferredFromAuthenticationFailure(
            string token, string error, string description)
        {
            // Arrange
            var server = CreateResourceServer();
            var client = server.HttpClient;

            var request = new HttpRequestMessage(HttpMethod.Get, "/");
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);

            // Act
            var response = await client.SendAsync(request);

            // Assert
            Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
            Assert.Equal($@"Bearer error=""{error}"", error_description=""{description}""",
                         response.Headers.WwwAuthenticate.ToString());
        }

        [Fact]
        public async Task HandleUnauthorizedAsync_ApplyChallenge_AllowsHandlingResponse()
        {
            // Arrange
            var server = CreateResourceServer(options =>
            {
                options.Events.OnApplyChallenge = context =>
                {
                    context.HandleResponse();
                    context.OwinContext.Response.Headers["X-Custom-Authentication-Header"] = "Bearer";

                    return Task.CompletedTask;
                };
            });

            var client = server.HttpClient;

            // Act
            var response = await client.GetAsync("/challenge");

            // Assert
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            Assert.Empty(response.Headers.WwwAuthenticate);
            Assert.Equal(new[] { "Bearer" }, response.Headers.GetValues("X-Custom-Authentication-Header"));
        }

        [Theory]
        [InlineData(null, null, null, null, null, "Bearer")]
        [InlineData("custom_error", null, null, null, null, @"Bearer error=""custom_error""")]
        [InlineData(null, "custom_error_description", null, null, null, @"Bearer error_description=""custom_error_description""")]
        [InlineData(null, null, "custom_error_uri", null, null, @"Bearer error_uri=""custom_error_uri""")]
        [InlineData(null, null, null, "custom_realm", null, @"Bearer realm=""custom_realm""")]
        [InlineData(null, null, null, null, "custom_scope", @"Bearer scope=""custom_scope""")]
        [InlineData("custom_error", "custom_error_description", "custom_error_uri", "custom_realm", "custom_scope",
                    @"Bearer realm=""custom_realm"", error=""custom_error"", " +
                    @"error_description=""custom_error_description"", " +
                    @"error_uri=""custom_error_uri"", scope=""custom_scope""")]
        public async Task HandleUnauthorizedAsync_ReturnsExpectedWwwAuthenticateHeader(
            string error, string description, string uri, string realm, string scope, string header)
        {
            // Arrange
            var server = CreateResourceServer(options =>
            {
                options.Events.OnApplyChallenge = context =>
                {
                    context.Error = error;
                    context.ErrorDescription = description;
                    context.ErrorUri = uri;
                    context.Realm = realm;
                    context.Scope = scope;

                    return Task.CompletedTask;
                };
            });

            var client = server.HttpClient;

            // Act
            var response = await client.GetAsync("/challenge");

            // Assert
            Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
            Assert.Equal(header, response.Headers.WwwAuthenticate.ToString());
        }

        private static TestServer CreateResourceServer(Action<OAuthIntrospectionOptions> configuration = null)
        {
            var server = CreateAuthorizationServer();

            return TestServer.Create(app =>
            {
                app.UseOAuthIntrospection(options =>
                {
                    options.AuthenticationMode = AuthenticationMode.Active;

                    options.ClientId = "Fabrikam";
                    options.ClientSecret = "B4657E03-D619";

                    options.Authority = server.BaseAddress;
                    options.HttpClient = server.HttpClient;
                    options.RequireHttpsMetadata = false;

                    // Note: overriding the default data protection provider is not necessary for the tests to pass,
                    // but is useful to ensure unnecessary keys are not persisted in testing environments, which also
                    // helps make the unit tests run faster, as no registry or disk access is required in this case.
                    options.DataProtectionProvider = new EphemeralDataProtectionProvider(new LoggerFactory());

                    // Run the configuration delegate
                    // registered by the unit tests.
                    configuration?.Invoke(options);
                });

                app.Map("/ticket", map => map.Run(async context =>
                {
                    var ticket = await context.Authentication.AuthenticateAsync(OAuthIntrospectionDefaults.AuthenticationScheme);
                    if (ticket == null)
                    {
                        context.Authentication.Challenge();

                        return;
                    }

                    context.Response.ContentType = "application/json";

                    // Return the authentication ticket as a JSON object.
                    await context.Response.WriteAsync(JsonConvert.SerializeObject(new
                    {
                        Claims = from claim in ticket.Identity.Claims
                                 select new { claim.Type, claim.Value },

                        Properties = from property in ticket.Properties.Dictionary
                                     select new { Name = property.Key, property.Value }
                    }));
                }));

                app.Map("/challenge", map => map.Run(context =>
                {
                    var properties = new AuthenticationProperties(new Dictionary<string, string>
                    {
                        [OAuthIntrospectionConstants.Properties.Error] = "custom_error",
                        [OAuthIntrospectionConstants.Properties.ErrorDescription] = "custom_error_description",
                        [OAuthIntrospectionConstants.Properties.ErrorUri] = "custom_error_uri",
                        [OAuthIntrospectionConstants.Properties.Realm] = "custom_realm",
                        [OAuthIntrospectionConstants.Properties.Scope] = "custom_scope",
                    });

                    context.Authentication.Challenge(properties, OAuthIntrospectionDefaults.AuthenticationScheme);

                    return Task.CompletedTask;
                }));

                app.Run(context =>
                {
                    if (context.Authentication.User == null ||
                       !context.Authentication.User.Identities.Any(identity => identity.IsAuthenticated))
                    {
                        context.Authentication.Challenge();

                        return Task.CompletedTask;
                    }

                    var subject = context.Authentication.User.FindFirst(OAuthIntrospectionConstants.Claims.Subject)?.Value;
                    if (string.IsNullOrEmpty(subject))
                    {
                        context.Authentication.Challenge();

                        return Task.CompletedTask;
                    }

                    return context.Response.WriteAsync(subject);
                });
            });
        }

        private static TestServer CreateAuthorizationServer()
        {
            return TestServer.Create(app =>
            {
                app.Map("/.well-known/openid-configuration", map => map.Run(async context =>
                {
                    using (var buffer = new MemoryStream())
                    using (var writer = new JsonTextWriter(new StreamWriter(buffer)))
                    {
                        var payload = new JObject
                        {
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

                app.Map("/connect/introspect", map => map.Run(async context =>
                {
                    using (var buffer = new MemoryStream())
                    using (var writer = new JsonTextWriter(new StreamWriter(buffer)))
                    {
                        var payload = new JObject();
                        var form = await context.Request.ReadFormAsync();

                        switch (form[OAuthIntrospectionConstants.Parameters.Token])
                        {
                            case "invalid-token":
                            {
                                payload[OAuthIntrospectionConstants.Claims.Active] = false;

                                break;
                            }

                            case "expired-token":
                            {
                                payload[OAuthIntrospectionConstants.Claims.Active] = true;
                                payload[OAuthIntrospectionConstants.Claims.Subject] = "Fabrikam";

                                // 1451602800 = 01/01/2016 - 00:00:00 AM.
                                payload[OAuthIntrospectionConstants.Claims.ExpiresAt] = 1455359642;

                                break;
                            }

                            case "valid-token":
                            {
                                payload[OAuthIntrospectionConstants.Claims.Active] = true;
                                payload[OAuthIntrospectionConstants.Claims.JwtId] = "jwt-token-identifier";
                                payload[OAuthIntrospectionConstants.Claims.Subject] = "Fabrikam";
                                payload[OAuthIntrospectionConstants.Claims.TokenUsage] =
                                    OAuthIntrospectionConstants.TokenUsages.AccessToken;

                                break;
                            }

                            case "valid-token-without-usage":
                            {
                                payload[OAuthIntrospectionConstants.Claims.Active] = true;
                                payload[OAuthIntrospectionConstants.Claims.JwtId] = "jwt-token-identifier";
                                payload[OAuthIntrospectionConstants.Claims.Subject] = "Fabrikam";

                                break;
                            }

                            case "valid-token-with-invalid-usage":
                            {
                                payload[OAuthIntrospectionConstants.Claims.Active] = true;
                                payload[OAuthIntrospectionConstants.Claims.JwtId] = "jwt-token-identifier";
                                payload[OAuthIntrospectionConstants.Claims.Subject] = "Fabrikam";
                                payload[OAuthIntrospectionConstants.Claims.TokenUsage] = "refresh_token";

                                break;
                            }

                            case "valid-token-with-scopes":
                            {
                                payload[OAuthIntrospectionConstants.Claims.Active] = true;
                                payload[OAuthIntrospectionConstants.Claims.JwtId] = "jwt-token-identifier";
                                payload[OAuthIntrospectionConstants.Claims.Subject] = "Fabrikam";
                                payload[OAuthIntrospectionConstants.Claims.Scope] = "openid profile";

                                break;
                            }

                            case "valid-token-with-single-audience":
                            {
                                payload[OAuthIntrospectionConstants.Claims.Active] = true;
                                payload[OAuthIntrospectionConstants.Claims.JwtId] = "jwt-token-identifier";
                                payload[OAuthIntrospectionConstants.Claims.Subject] = "Fabrikam";
                                payload[OAuthIntrospectionConstants.Claims.Audience] = "http://www.contoso.com/";

                                break;
                            }

                            case "valid-token-with-multiple-audiences":
                            {
                                payload[OAuthIntrospectionConstants.Claims.Active] = true;
                                payload[OAuthIntrospectionConstants.Claims.JwtId] = "jwt-token-identifier";
                                payload[OAuthIntrospectionConstants.Claims.Subject] = "Fabrikam";
                                payload[OAuthIntrospectionConstants.Claims.Audience] = JArray.FromObject(new[]
                                {
                                    "http://www.contoso.com/", "http://www.fabrikam.com/"
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
