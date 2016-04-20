/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/aspnet-contrib/AspNet.Security.OAuth.Extensions for more information
 * concerning the license and the contributors participating to this project.
 */

namespace Owin.Security.OAuth.Introspection {
    public static class OAuthIntrospectionConstants {
        public static class Claims {
            public const string Active = "active";
            public const string Audience = "aud";
            public const string ExpiresAt = "exp";
            public const string IssuedAt = "iat";
            public const string Jti = "jti";
            public const string NotBefore = "nbf";
            public const string Scope = "scope";
            public const string Subject = "sub";
            public const string TokenType = "token_type";
            public const string Username = "username";
        }

        public static class Headers {
            public const string Authorization = "Authorization";
        }

        public static class Metadata {
            public const string IntrospectionEndpoint = "introspection_endpoint";
        }

        public static class Parameters {
            public const string Token = "token";
            public const string TokenTypeHint = "token_type_hint";
        }

        public static class Properties {
            public const string Audiences = ".audiences";
            public const string Scopes = ".scopes";
            public const string TicketId = ".ticket_id";
            public const string Token = "access_token";
        }

        public static class TokenTypes {
            public const string AccessToken = "access_token";
        }
    }
}
