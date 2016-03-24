using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;

namespace AspNet.Security.OAuth.Validation.Events
{
    public class ReceivingTokenContext : BaseControlContext
    {
        public ReceivingTokenContext(HttpContext context, OAuthValidationOptions options)
            : base(context)
        {
        }
        public OAuthValidationOptions Options { get; }
        /// <summary>
        /// Bearer Token. This will give application an opportunity to retrieve token from an alternation location.
        /// </summary>
        public string Token { get; set; }
    }
}
