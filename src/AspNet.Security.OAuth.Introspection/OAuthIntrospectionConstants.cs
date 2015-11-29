namespace AspNet.Security.OAuth.Introspection {
    public static class OAuthIntrospectionConstants {
        public static class Claims {
            public const string Active = "active";
            public const string Audience = "aud";
            public const string ExpiresAt = "exp";
            public const string IssuedAt = "iat";
            public const string NotBefore = "nbf";
            public const string Scope = "scope";
            public const string Subject = "sub";
            public const string TokenType = "token_type";
            public const string Username = "username";
        }

        public static class Metadata {
            public const string IntrospectionEndpoint = "introspection_endpoint";
        }

        public static class Parameters {
            public const string Token = "token";
            public const string TokenTypeHint = "token_type_hint";
        }

        public static class TokenTypes {
            public const string AccessToken = "access_token";
        }
    }
}
