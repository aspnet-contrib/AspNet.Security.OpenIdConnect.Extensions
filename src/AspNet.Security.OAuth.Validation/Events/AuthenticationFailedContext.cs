using Microsoft.AspNetCore.Http;
using System;

namespace AspNet.Security.OAuth.Validation.Events
{
    public class AuthenticationFailedContext : BaseValidationContext
    {
        public AuthenticationFailedContext(HttpContext context, OAuthValidationOptions options)
            : base(context, options)
        {
        }

        public Exception Exception { get; set; }
    }
}
