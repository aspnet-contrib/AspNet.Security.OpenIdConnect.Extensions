/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/aspnet-contrib/AspNet.Security.OAuth.Extensions for more information
 * concerning the license and the contributors participating to this project.
 */

using System.Threading.Tasks;

namespace AspNet.Security.OAuth.Validation {
    /// <summary>
    /// Allows customization of validation handling within the middleware.
    /// </summary>
    public interface IOAuthValidationEvents {
        /// <summary>
        /// Invoked when a token is to be parsed from a newly-received request.
        /// </summary>
        Task ParseAccessToken(ParseAccessTokenContext context);

        /// <summary>
        /// Invoked when a token is to be validated, before final processing.
        /// </summary>
        Task ValidateToken(ValidateTokenContext context);
    }
}
