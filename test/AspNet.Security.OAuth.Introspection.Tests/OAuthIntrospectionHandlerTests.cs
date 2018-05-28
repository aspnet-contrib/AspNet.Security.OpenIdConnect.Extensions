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
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using Xunit;

namespace AspNet.Security.OAuth.Introspection.Tests
{
    public class OAuthIntrospectionHandlerTests
    {
        [Theory]
        [InlineData(null, null)]
        [InlineData("", "")]
        [InlineData("client_id", null)]
        [InlineData("client_id", "")]
        [InlineData(null, "client_secret")]
        [InlineData("", "client_secret")]
        public async Task InitializeOptions_ThrowsAnExceptionForMissingCredentials(string identifier, string secret)
        {
            // Arrange
            var server = CreateResourceServer(options =>
            {
                options.Authority = new Uri("http://www.fabrikam.com/");
                options.ClientId = identifier;
                options.ClientSecret = secret;
                options.RequireHttpsMetadata = false;
            });

            var client = server.CreateClient();

            // Act and assert
            var exception = await Assert.ThrowsAsync<InvalidOperationException>(delegate
            {
                return client.GetAsync("/initialization");
            });

            Assert.Equal("Client credentials must be configured.", exception.Message);
        }

        [Fact]
        public async Task InitializeOptions_ThrowsAnExceptionForMissingEndpoint()
        {
            // Arrange
            var server = CreateResourceServer(options =>
            {
                options.Configuration = new OAuthIntrospectionConfiguration
                {
                    IntrospectionEndpoint = null
                };
            });

            var client = server.CreateClient();

            // Act and assert
            var exception = await Assert.ThrowsAsync<InvalidOperationException>(delegate
            {
                return client.GetAsync("/initialization");
            });

            Assert.Equal("The introspection endpoint address cannot be null or empty.", exception.Message);
        }

        [Fact]
        public async Task InitializeOptions_ThrowsAnExceptionForMissingAuthority()
        {
            // Arrange
            var server = CreateResourceServer(options =>
            {
                options.Authority = null;
                options.MetadataAddress = null;
            });

            var client = server.CreateClient();

            // Act and assert
            var exception = await Assert.ThrowsAsync<InvalidOperationException>(delegate
            {
                return client.GetAsync("/initialization");
            });

            Assert.Equal("The authority or an absolute metadata endpoint address must be provided.", exception.Message);
        }

        [Fact]
        public async Task InitializeOptions_ThrowsAnExceptionForRelativeAuthority()
        {
            // Arrange
            var server = CreateResourceServer(options =>
            {
                options.Authority = new Uri("/relative-path", UriKind.Relative);
            });

            var client = server.CreateClient();

            // Act and assert
            var exception = await Assert.ThrowsAsync<InvalidOperationException>(delegate
            {
                return client.GetAsync("/initialization");
            });

            Assert.Equal("The authority must be provided and must be an absolute URL.", exception.Message);
        }

        [Theory]
        [InlineData("http://www.fabrikam.com/path?param=value")]
        [InlineData("http://www.fabrikam.com/path#param=value")]
        public async Task InitializeOptions_ThrowsAnExceptionForInvalidAuthority(string authority)
        {
            // Arrange
            var server = CreateResourceServer(options =>
            {
                options.Authority = new Uri(authority);
            });

            var client = server.CreateClient();

            // Act and assert
            var exception = await Assert.ThrowsAsync<InvalidOperationException>(delegate
            {
                return client.GetAsync("/initialization");
            });

            Assert.Equal("The authority cannot contain a fragment or a query string.", exception.Message);
        }

        [Fact]
        public async Task InitializeOptions_ThrowsAnExceptionForNonHttpsAuthority()
        {
            // Arrange
            var server = CreateResourceServer(options =>
            {
                options.Authority = new Uri("http://www.fabrikam.com/");
                options.RequireHttpsMetadata = true;
            });

            var client = server.CreateClient();

            // Act and assert
            var exception = await Assert.ThrowsAsync<InvalidOperationException>(delegate
            {
                return client.GetAsync("/initialization");
            });

            Assert.Equal("The metadata endpoint address must be a HTTPS URL when " +
                         "'RequireHttpsMetadata' is not set to 'false'.", exception.Message);
        }

        [Fact]
        public async Task HandleAuthenticateAsync_MissingTokenCausesInvalidAuthentication()
        {
            // Arrange
            var server = CreateResourceServer();
            var client = server.CreateClient();

            var request = new HttpRequestMessage(HttpMethod.Get, "/");

            // Act
            var response = await client.SendAsync(request);

            // Assert
            Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        }

        [Fact]
        public async Task HandleAuthenticateAsync_InvalidTokenCausesInvalidAuthentication()
        {
            // Arrange
            var server = CreateResourceServer();
            var client = server.CreateClient();

            var request = new HttpRequestMessage(HttpMethod.Get, "/");
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", "invalid-token");

            // Act
            var response = await client.SendAsync(request);

            // Assert
            Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        }

        [Fact]
        public async Task HandleAuthenticateAsync_ValidTokenAllowsSuccessfulAuthentication()
        {
            // Arrange
            var server = CreateResourceServer();
            var client = server.CreateClient();

            var request = new HttpRequestMessage(HttpMethod.Get, "/");
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", "valid-token");

            // Act
            var response = await client.SendAsync(request);

            // Assert
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            Assert.Equal("Fabrikam", await response.Content.ReadAsStringAsync());
        }

        [Fact]
        public async Task HandleAuthenticateAsync_MissingTokenUsageAllowsSuccessfulAuthentication()
        {
            // Arrange
            var server = CreateResourceServer();
            var client = server.CreateClient();

            var request = new HttpRequestMessage(HttpMethod.Get, "/");
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", "valid-token-without-usage");

            // Act
            var response = await client.SendAsync(request);

            // Assert
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            Assert.Equal("Fabrikam", await response.Content.ReadAsStringAsync());
        }

        [Fact]
        public async Task HandleAuthenticateAsync_InvalidTokenUsageCausesInvalidAuthentication()
        {
            // Arrange
            var server = CreateResourceServer();
            var client = server.CreateClient();

            var request = new HttpRequestMessage(HttpMethod.Get, "/");
            request.Headers.Authorization = new AuthenticationHeaderValue(
                "Bearer", "valid-token-with-invalid-usage");

            // Act
            var response = await client.SendAsync(request);

            // Assert
            Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        }

        [Fact]
        public async Task HandleAuthenticateAsync_ValidTokenUsageAllowsSuccessfulAuthentication()
        {
            // Arrange
            var server = CreateResourceServer();
            var client = server.CreateClient();

            var request = new HttpRequestMessage(HttpMethod.Get, "/");
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", "valid-token");

            // Act
            var response = await client.SendAsync(request);

            // Assert
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            Assert.Equal("Fabrikam", await response.Content.ReadAsStringAsync());
        }

        [Fact]
        public async Task HandleAuthenticateAsync_ExpiredTicketCausesInvalidAuthentication()
        {
            // Arrange
            var server = CreateResourceServer();
            var client = server.CreateClient();

            var request = new HttpRequestMessage(HttpMethod.Get, "/");
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", "expired-token");

            // Act
            var response = await client.SendAsync(request);

            // Assert
            Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        }

        [Fact]
        public async Task HandleAuthenticateAsync_MissingAudienceCausesInvalidAuthentication()
        {
            // Arrange
            var server = CreateResourceServer(options =>
            {
                options.Audiences.Add("http://www.fabrikam.com/");
            });

            var client = server.CreateClient();

            var request = new HttpRequestMessage(HttpMethod.Get, "/");
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", "valid-token");

            // Act
            var response = await client.SendAsync(request);

            // Assert
            Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        }

        [Fact]
        public async Task HandleAuthenticateAsync_InvalidAudienceCausesInvalidAuthentication()
        {
            // Arrange
            var server = CreateResourceServer(options =>
            {
                options.Audiences.Add("http://www.fabrikam.com/");
            });

            var client = server.CreateClient();

            var request = new HttpRequestMessage(HttpMethod.Get, "/");
            request.Headers.Authorization = new AuthenticationHeaderValue(
                "Bearer", "valid-token-with-single-audience");

            // Act
            var response = await client.SendAsync(request);

            // Assert
            Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        }

        [Fact]
        public async Task HandleAuthenticateAsync_AnyMatchingAudienceCausesSuccessfulAuthentication()
        {
            // Arrange
            var server = CreateResourceServer(options =>
            {
                options.Audiences.Add("http://www.contoso.com/");
                options.Audiences.Add("http://www.fabrikam.com/");
            });

            var client = server.CreateClient();

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
        public async Task HandleAuthenticateAsync_ValidAudienceAllowsSuccessfulAuthentication()
        {
            // Arrange
            var server = CreateResourceServer(options =>
            {
                options.Audiences.Add("http://www.fabrikam.com/");
            });

            var client = server.CreateClient();

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
        public async Task HandleAuthenticateAsync_MultipleMatchingAudienceCausesSuccessfulAuthentication()
        {
            // Arrange
            var server = CreateResourceServer(options =>
            {
                options.Audiences.Add("http://www.fabrikam.com/");
                options.Audiences.Add("http://www.google.com/");
            });

            var client = server.CreateClient();

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
        public async Task HandleAuthenticateAsync_AuthenticationTicketContainsRequiredClaims()
        {
            // Arrange
            var server = CreateResourceServer();
            var client = server.CreateClient();

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
        public async Task HandleAuthenticateAsync_AuthenticationTicketContainsRequiredProperties()
        {
            // Arrange
            var server = CreateResourceServer(options =>
            {
                options.SaveToken = true;
            });

            var client = server.CreateClient();

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

            Assert.Contains(properties, property => property.Name == ".Token.access_token" &&
                                                    property.Value == "valid-token");
        }

        [Fact]
        public async Task HandleAuthenticateAsync_InvalidReplacedTokenCausesInvalidAuthentication()
        {
            // Arrange
            var server = CreateResourceServer(options =>
            {
                options.Events.OnRetrieveToken = context =>
                {
                    context.Token = "invalid-token";

                    return Task.FromResult(0);
                };
            });

            var client = server.CreateClient();

            var request = new HttpRequestMessage(HttpMethod.Get, "/");
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", "valid-token");

            // Act
            var response = await client.SendAsync(request);

            // Assert
            Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        }

        [Fact]
        public async Task HandleAuthenticateAsync_ValidReplacedTokenCausesSuccessfulAuthentication()
        {
            // Arrange
            var server = CreateResourceServer(options =>
            {
                options.Events.OnRetrieveToken = context =>
                {
                    context.Token = "valid-token";

                    return Task.FromResult(0);
                };
            });

            var client = server.CreateClient();

            var request = new HttpRequestMessage(HttpMethod.Get, "/");
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", "invalid-token");

            // Act
            var response = await client.SendAsync(request);

            // Assert
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            Assert.Equal("Fabrikam", await response.Content.ReadAsStringAsync());
        }

        [Fact]
        public async Task HandleAuthenticateAsync_FailFromReceiveTokenCausesInvalidAuthentication()
        {
            // Arrange
            var server = CreateResourceServer(options =>
            {
                options.Events.OnRetrieveToken = context =>
                {
                    context.Fail(new Exception());

                    return Task.FromResult(0);
                };
            });

            var client = server.CreateClient();

            var request = new HttpRequestMessage(HttpMethod.Get, "/");
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", "valid-token");

            // Act
            var response = await client.SendAsync(request);

            // Assert
            Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        }

        [Fact]
        public async Task HandleAuthenticateAsync_NoResultFromReceiveTokenCauseInvalidAuthentication()
        {
            // Arrange
            var server = CreateResourceServer(options =>
            {
                options.Events.OnRetrieveToken = context =>
                {
                    context.NoResult();

                    return Task.FromResult(0);
                };
            });

            var client = server.CreateClient();

            var request = new HttpRequestMessage(HttpMethod.Get, "/");
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", "valid-token");

            // Act
            var response = await client.SendAsync(request);

            // Assert
            Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        }

        [Fact]
        public async Task HandleAuthenticateAsync_SuccessFromReceiveTokenCauseSuccessfulAuthentication()
        {
            // Arrange
            var server = CreateResourceServer(options =>
            {
                options.Events.OnRetrieveToken = context =>
                {
                    var identity = new ClaimsIdentity(OAuthIntrospectionDefaults.AuthenticationScheme);
                    identity.AddClaim(new Claim(OAuthIntrospectionConstants.Claims.Subject, "Fabrikam"));

                    context.Principal = new ClaimsPrincipal(identity);
                    context.Success();

                    return Task.FromResult(0);
                };
            });

            var client = server.CreateClient();

            var request = new HttpRequestMessage(HttpMethod.Get, "/");
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", "invalid-token");

            // Act
            var response = await client.SendAsync(request);

            // Assert
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            Assert.Equal("Fabrikam", await response.Content.ReadAsStringAsync());
        }

        [Fact]
        public async Task HandleAuthenticateAsync_FailFromValidateTokenCausesInvalidAuthentication()
        {
            // Arrange
            var server = CreateResourceServer(options =>
            {
                options.Events.OnValidateToken = context =>
                {
                    context.Fail(new Exception());

                    return Task.FromResult(0);
                };
            });

            var client = server.CreateClient();

            var request = new HttpRequestMessage(HttpMethod.Get, "/");
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", "valid-token");

            // Act
            var response = await client.SendAsync(request);

            // Assert
            Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        }

        [Fact]
        public async Task HandleAuthenticateAsync_NoResultFromValidateTokenCauseInvalidAuthentication()
        {
            // Arrange
            var server = CreateResourceServer(options =>
            {
                options.Events.OnValidateToken = context =>
                {
                    context.NoResult();

                    return Task.FromResult(0);
                };
            });

            var client = server.CreateClient();

            var request = new HttpRequestMessage(HttpMethod.Get, "/");
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", "valid-token");

            // Act
            var response = await client.SendAsync(request);

            // Assert
            Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        }

        [Fact]
        public async Task HandleAuthenticateAsync_SuccessFromValidateTokenCauseSuccessfulAuthentication()
        {
            // Arrange
            var server = CreateResourceServer(options =>
            {
                options.Events.OnValidateToken = context =>
                {
                    var identity = new ClaimsIdentity(OAuthIntrospectionDefaults.AuthenticationScheme);
                    identity.AddClaim(new Claim(OAuthIntrospectionConstants.Claims.Subject, "Contoso"));

                    context.Principal = new ClaimsPrincipal(identity);
                    context.Success();

                    return Task.FromResult(0);
                };
            });

            var client = server.CreateClient();

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

                    return Task.FromResult(0);
                };
            });

            var client = server.CreateClient();

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
            var client = server.CreateClient();

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
                    context.HttpContext.Response.Headers["X-Custom-Authentication-Header"] = "Bearer";

                    return Task.FromResult(0);
                };
            });

            var client = server.CreateClient();

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

                    return Task.FromResult(0);
                };
            });

            var client = server.CreateClient();

            // Act
            var response = await client.GetAsync("/challenge");

            // Assert
            Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
            Assert.Equal(header, response.Headers.WwwAuthenticate.ToString());
        }

        [Fact]
        public async Task HandleAuthenticateAsync_CopyMatchingHttpHeaders_NotSet()
        {
            // Arrange
            var correlationId = Guid.NewGuid().ToString();
            var forwardedFor = "1.1.1.1";
            var xCorrelationId = "X-Correlation-Id";
            var xForwardedFor = "X-Forwarded-For";
            var someHttpHeader = "Some-Http-Header";

            var server = CreateResourceServer(options =>
            {
                options.Events.OnSendIntrospectionRequest = context =>
                {
                    // Assert
                    var headers = context.Request.Headers;
                    var keys = headers.Select(x => x.Key).ToArray();

                    Assert.DoesNotContain(new[] { xCorrelationId, xForwardedFor, someHttpHeader }, (x => keys.Contains(x)));

                    return Task.FromResult(0);
                };
            });

            var client = server.CreateClient();

            var request = new HttpRequestMessage(HttpMethod.Get, "/");
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", "valid-token");
            request.Headers.Add(xCorrelationId, new List<string> { correlationId });
            request.Headers.Add(xForwardedFor, new List<string> { forwardedFor });
            request.Headers.Add(someHttpHeader, new List<string> { "header-value" });

            // Act
            var response = await client.SendAsync(request);
            var content = await response.Content.ReadAsStringAsync();

            // Assert
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        }

        [Fact]
        public async Task HandleAuthenticateAsync_CopyMatchingHttpHeaders_DoesNotContainNonMatchedHeaders()
        {
            // Arrange
            var correlationId = Guid.NewGuid().ToString();
            var forwardedFor = "1.1.1.1";
            var xCorrelationId = "X-Correlation-Id";
            var xForwardedFor = "X-Forwarded-For";
            var someHttpHeader = "Some-Http-Header";

            var server = CreateResourceServer(options =>
            {
                options.SetValuesToMatchFromRequestHttpHeaders(null, new[] { "X-" });
                options.Events.OnSendIntrospectionRequest = context =>
                {
                    // Assert
                    var headers = context.Request.Headers;
                    var keys = headers.Select(x => x.Key).ToArray();

                    Assert.DoesNotContain(new[] { someHttpHeader }, (x => keys.Contains(x)));

                    return Task.FromResult(0);
                };
            });

            var client = server.CreateClient();

            var request = new HttpRequestMessage(HttpMethod.Get, "/");
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", "valid-token");
            request.Headers.Add(xCorrelationId, new List<string> { correlationId });
            request.Headers.Add(xForwardedFor, new List<string> { forwardedFor });
            request.Headers.Add(someHttpHeader, new List<string> { "header-value" });

            // Act
            var response = await client.SendAsync(request);
            var content = await response.Content.ReadAsStringAsync();

            // Assert
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        }

        [Fact]
        public async Task HandleAuthenticateAsync_CopyMatchingHttpHeaders_UsingMulitplePrefixes()
        {
            // Arrange
            var correlationId = Guid.NewGuid().ToString();
            var forwardedFor = "1.1.1.1";
            var headerPrefixX = "X-";
            var headerPrefixY = "Y-";
            var xCorrelationId = "X-Correlation-Id";
            var xForwardedFor = "Y-Forwarded-For";
            var someHttpHeader = "Some-Http-Header";

            var server = CreateResourceServer(options =>
            {
                options.SetValuesToMatchFromRequestHttpHeaders(null, new[] { headerPrefixX, headerPrefixY });
                options.Events.OnSendIntrospectionRequest = context =>
                {
                    // Assert
                    var headers = context.Request.Headers;
                    var keys = headers.Select(x => x.Key).ToArray();

                    Assert.Contains(new[] { xCorrelationId, xForwardedFor }, (x => keys.Contains(x)));
                    Assert.Contains(correlationId, headers.Single(x => x.Key.Equals(xCorrelationId, StringComparison.Ordinal)).Value);
                    Assert.Contains(forwardedFor, headers.Single(x => x.Key.Equals(xForwardedFor, StringComparison.Ordinal)).Value);

                    return Task.FromResult(0);
                };
            });

            var client = server.CreateClient();

            var request = new HttpRequestMessage(HttpMethod.Get, "/");
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", "valid-token");
            request.Headers.Add(xCorrelationId, new List<string> { correlationId });
            request.Headers.Add(xForwardedFor, new List<string> { forwardedFor });
            request.Headers.Add(someHttpHeader, new List<string> { "header-value" });

            // Act
            var response = await client.SendAsync(request);
            var content = await response.Content.ReadAsStringAsync();

            // Assert
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        }

        [Fact]
        public async Task HandleAuthenticateAsync_CopyMatchingHttpHeaders_UsingSinglePrefix()
        {
            // Arrange
            var correlationId = Guid.NewGuid().ToString();
            var forwardedFor = "1.1.1.1";
            var xCorrelationId = "X-Correlation-Id";
            var xForwardedFor = "X-Forwarded-For";
            var headerPrefix = "X-";

            var server = CreateResourceServer(options =>
            {
                options.SetValuesToMatchFromRequestHttpHeaders(null, new[] { headerPrefix });
                options.Events.OnSendIntrospectionRequest = context =>
                {
                    // Assert
                    var headers = context.Request.Headers;
                    var keys = headers.Select(x => x.Key).ToArray();

                    Assert.Contains(new[] { xCorrelationId, xForwardedFor }, (x => keys.Contains(x)));
                    Assert.Contains(correlationId, headers.Single(x => x.Key.Equals(xCorrelationId, StringComparison.Ordinal)).Value);
                    Assert.Contains(forwardedFor, headers.Single(x => x.Key.Equals(xForwardedFor, StringComparison.Ordinal)).Value);

                    return Task.FromResult(0);
                };
            });

            var client = server.CreateClient();

            var request = new HttpRequestMessage(HttpMethod.Get, "/");
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", "valid-token");
            request.Headers.Add(xCorrelationId, new List<string> { correlationId });
            request.Headers.Add(xForwardedFor, new List<string> { forwardedFor });
            request.Headers.Add("Some-Http-Header", new List<string> { "header-value" });

            // Act
            var response = await client.SendAsync(request);
            var content = await response.Content.ReadAsStringAsync();

            // Assert
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        }

        [Fact]
        public async Task HandleAuthenticateAsync_CopyMatchingHttpHeaders_UsingSingleExactMatch()
        {
            // Arrange
            var correlationId = Guid.NewGuid().ToString();
            var forwardedFor = "1.1.1.1";
            var xCorrelationId = "X-Correlation-Id";
            var xForwardedFor = "X-Forwarded-For";

            var server = CreateResourceServer(options =>
            {
                options.SetValuesToMatchFromRequestHttpHeaders(new[] { xCorrelationId }, null);
                options.Events.OnSendIntrospectionRequest = context =>
                {
                    // Assert
                    var headers = context.Request.Headers;
                    var keys = headers.Select(x => x.Key).ToArray();

                    Assert.Contains(new[] { xCorrelationId }, (x => keys.Contains(x)));
                    Assert.Contains(correlationId, headers.Single(x => x.Key.Equals(xCorrelationId, StringComparison.Ordinal)).Value);

                    return Task.FromResult(0);
                };
            });

            var client = server.CreateClient();

            var request = new HttpRequestMessage(HttpMethod.Get, "/");
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", "valid-token");
            request.Headers.Add(xCorrelationId, new List<string> { correlationId });
            request.Headers.Add(xForwardedFor, new List<string> { forwardedFor });
            request.Headers.Add("Some-Http-Header", new List<string> { "header-value" });

            // Act
            var response = await client.SendAsync(request);
            var content = await response.Content.ReadAsStringAsync();

            // Assert
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        }

        [Fact]
        public async Task HandleAuthenticateAsync_CopyMatchingHttpHeaders_UsingMultipleExactMatches()
        {
            // Arrange
            var correlationId = Guid.NewGuid().ToString();
            var forwardedFor = "1.1.1.1";
            var xCorrelationId = "X-Correlation-Id";
            var xForwardedFor = "X-Forwarded-For";

            var server = CreateResourceServer(options =>
            {
                options.SetValuesToMatchFromRequestHttpHeaders(new[] { xCorrelationId, xForwardedFor }, null);
                options.Events.OnSendIntrospectionRequest = context =>
                {
                    // Assert
                    var headers = context.Request.Headers;
                    var keys = headers.Select(x => x.Key).ToArray();

                    Assert.Contains(new[] { xCorrelationId, xForwardedFor }, (x => keys.Contains(x)));
                    Assert.Contains(correlationId, headers.Single(x => x.Key.Equals(xCorrelationId, StringComparison.Ordinal)).Value);
                    Assert.Contains(forwardedFor, headers.Single(x => x.Key.Equals(xForwardedFor, StringComparison.Ordinal)).Value);

                    return Task.FromResult(0);
                };
            });

            var client = server.CreateClient();

            var request = new HttpRequestMessage(HttpMethod.Get, "/");
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", "valid-token");
            request.Headers.Add(xCorrelationId, new List<string> { correlationId });
            request.Headers.Add(xForwardedFor, new List<string> { forwardedFor });
            request.Headers.Add("Some-Http-Header", new List<string> { "header-value" });

            // Act
            var response = await client.SendAsync(request);
            var content = await response.Content.ReadAsStringAsync();

            // Assert
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        }

        [Fact]
        public async Task HandleAuthenticateAsync_CopyMatchingHttpHeaders_UsingExactAndPrefixMatches()
        {
            // Arrange
            var correlationId = Guid.NewGuid().ToString();
            var forwardedFor = "1.1.1.1";
            var xCorrelationId = "X-Correlation-Id";
            var xForwardedFor = "X-Forwarded-For";
            var aHttpHeader = "A-SomeHeader";
            var aNotherHeader = "A-NotherHeader";
            var headerPrefixA = "A-";
            var ahttpHeaderVal = "header-value";
            var aNotherHeaderVal = "another-header-value";

            var server = CreateResourceServer(options =>
            {
                options.SetValuesToMatchFromRequestHttpHeaders(new[] { xCorrelationId, xForwardedFor }, new[] { headerPrefixA });
                options.Events.OnSendIntrospectionRequest = context =>
                {
                    // Assert
                    var headers = context.Request.Headers;
                    var keys = headers.Select(x => x.Key).ToArray();

                    Assert.Contains(new[] { xCorrelationId, xForwardedFor, aHttpHeader, aNotherHeader }, (x => keys.Contains(x)));
                    Assert.Contains(correlationId, headers.Single(x => x.Key.Equals(xCorrelationId, StringComparison.Ordinal)).Value);
                    Assert.Contains(forwardedFor, headers.Single(x => x.Key.Equals(xForwardedFor, StringComparison.Ordinal)).Value);

                    Assert.Contains(ahttpHeaderVal, headers.Single(x => x.Key.Equals(aHttpHeader, StringComparison.Ordinal)).Value);
                    Assert.Contains(aNotherHeaderVal, headers.Single(x => x.Key.Equals(aNotherHeader, StringComparison.Ordinal)).Value);

                    return Task.FromResult(0);
                };
            });

            var client = server.CreateClient();

            var request = new HttpRequestMessage(HttpMethod.Get, "/");
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", "valid-token");
            request.Headers.Add(xCorrelationId, new List<string> { correlationId });
            request.Headers.Add(xForwardedFor, new List<string> { forwardedFor });
            request.Headers.Add(aHttpHeader, new List<string> { ahttpHeaderVal });
            request.Headers.Add(aNotherHeader, new List<string> { aNotherHeaderVal });
            request.Headers.Add("Some-Http-Header", new List<string> { "header-value" });

            // Act
            var response = await client.SendAsync(request);
            var content = await response.Content.ReadAsStringAsync();

            // Assert
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        }

        private static TestServer CreateResourceServer(Action<OAuthIntrospectionOptions> configuration = null)
        {
            var server = CreateAuthorizationServer();

            var builder = new WebHostBuilder();
            builder.UseEnvironment("Testing");

            builder.ConfigureLogging(options => options.AddDebug());

            builder.ConfigureServices(services =>
            {
                services.AddDistributedMemoryCache();

                services.AddAuthentication()
                    .AddOAuthIntrospection(options =>
                    {
                        options.ClientId = "Fabrikam";
                        options.ClientSecret = "B4657E03-D619";

                        options.Authority = server.BaseAddress;
                        options.HttpClient = server.CreateClient();
                        options.RequireHttpsMetadata = false;

                        // Note: overriding the default data protection provider is not necessary for the tests to pass,
                        // but is useful to ensure unnecessary keys are not persisted in testing environments, which also
                        // helps make the unit tests run faster, as no registry or disk access is required in this case.
                        options.DataProtectionProvider = new EphemeralDataProtectionProvider(new LoggerFactory());

                        // Run the configuration delegate
                        // registered by the unit tests.
                        configuration?.Invoke(options);
                    });
            });

            builder.Configure(app =>
            {
                app.Map("/ticket", map => map.Run(async context =>
                {
                    var result = await context.AuthenticateAsync(OAuthIntrospectionDefaults.AuthenticationScheme);
                    if (result.Principal == null)
                    {
                        await context.ChallengeAsync();

                        return;
                    }

                    context.Response.ContentType = "application/json";

                    // Return the authentication ticket as a JSON object.
                    await context.Response.WriteAsync(JsonConvert.SerializeObject(new
                    {
                        Claims = from claim in result.Principal.Claims
                                 select new { claim.Type, claim.Value },

                        Properties = from property in result.Properties.Items
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

                    return context.ChallengeAsync(OAuthIntrospectionDefaults.AuthenticationScheme, properties);
                }));

                app.Run(async context =>
                {
                    var result = await context.AuthenticateAsync(OAuthIntrospectionDefaults.AuthenticationScheme);
                    if (result.Principal == null)
                    {
                        await context.ChallengeAsync(OAuthIntrospectionDefaults.AuthenticationScheme);

                        return;
                    }

                    var subject = result.Principal.FindFirst(OAuthIntrospectionConstants.Claims.Subject)?.Value;
                    if (string.IsNullOrEmpty(subject))
                    {
                        await context.ChallengeAsync(OAuthIntrospectionDefaults.AuthenticationScheme);

                        return;
                    }

                    await context.Response.WriteAsync(subject);
                });
            });

            return new TestServer(builder);
        }

        private static TestServer CreateAuthorizationServer()
        {
            var builder = new WebHostBuilder();
            builder.UseEnvironment("Testing");

            builder.ConfigureLogging(options => options.AddDebug());

            builder.ConfigureServices(services =>
            {
                services.AddAuthentication();
                services.AddDistributedMemoryCache();
                services.AddLogging();
            });

            builder.Configure(app =>
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
                        await buffer.CopyToAsync(context.Response.Body, 4096, context.RequestAborted);
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
                        await buffer.CopyToAsync(context.Response.Body, 4096, context.RequestAborted);
                    }
                }));
            });

            return new TestServer(builder);
        }
    }
}
