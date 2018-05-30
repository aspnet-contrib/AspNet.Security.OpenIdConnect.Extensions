/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/aspnet-contrib/AspNet.Security.OAuth.Extensions for more information
 * concerning the license and the contributors participating to this project.
 */

using JetBrains.Annotations;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;

namespace AspNet.Security.OAuth.Validation
{
    /// <summary>
    /// Allows custom decryption of access tokens.
    /// </summary>
    public class DecryptTokenContext : ResultContext<OAuthValidationOptions>
    {
        public DecryptTokenContext(
            [NotNull] HttpContext context,
            [NotNull] AuthenticationScheme scheme,
            [NotNull] OAuthValidationOptions options,
            [NotNull] string token)
            : base(context, scheme, options)
        {
            Token = token;
        }

        /// <summary>
        /// Gets the access token.
        /// </summary>
        public string Token { get; }

        /// <summary>
        /// Gets or sets the data format used to deserialize the authentication ticket.
        /// </summary>
        public ISecureDataFormat<AuthenticationTicket> DataFormat { get; set; }
    }
}
