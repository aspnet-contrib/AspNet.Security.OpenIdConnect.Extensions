using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using System;

namespace AspNet.Security.OAuth.Validation.Events
{
    public class AuthenticationFailedContext : BaseControlContext
    {
        public AuthenticationFailedContext(HttpContext context, OAuthValidationOptions options)
            : base(context)
        {
            Options = options;
        }
        public OAuthValidationOptions Options { get; }
        public Exception Exception { get; set; }
    }
}
