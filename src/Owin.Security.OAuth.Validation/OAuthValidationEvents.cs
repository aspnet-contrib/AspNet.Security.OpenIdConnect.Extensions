/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/aspnet-contrib/AspNet.Security.OAuth.Extensions for more information
 * concerning the license and the contributors participating to this project.
 */

using System;
using System.Threading.Tasks;

namespace Owin.Security.OAuth.Validation
{
    /// <summary>
    /// Allows customization of validation handling within the middleware.
    /// </summary>
    public class OAuthValidationEvents
    {
        /// <summary>
        /// Invoked when a challenge response is returned to the caller.
        /// </summary>
        public Func<ApplyChallengeContext, Task> OnApplyChallenge { get; set; } = context => Task.CompletedTask;

        /// <summary>
        /// Invoked when a ticket is to be created from an access token.
        /// </summary>
        public Func<CreateTicketContext, Task> OnCreateTicket { get; set; } = context => Task.CompletedTask;

        /// <summary>
        /// Invoked when a token is to be decrypted.
        /// </summary>
        public Func<DecryptTokenContext, Task> OnDecryptToken { get; set; } = context => Task.CompletedTask;

        /// <summary>
        /// Invoked when a token is to be parsed from a newly-received request.
        /// </summary>
        public Func<RetrieveTokenContext, Task> OnRetrieveToken { get; set; } = context => Task.CompletedTask;

        /// <summary>
        /// Invoked when a token is to be validated, before final processing.
        /// </summary>
        public Func<ValidateTokenContext, Task> OnValidateToken { get; set; } = context => Task.CompletedTask;

        /// <summary>
        /// Invoked when a challenge response is returned to the caller.
        /// </summary>
        public virtual Task ApplyChallenge(ApplyChallengeContext context) => OnApplyChallenge(context);

        /// <summary>
        /// Invoked when a ticket is to be created from an access token.
        /// </summary>
        public virtual Task CreateTicket(CreateTicketContext context) => OnCreateTicket(context);

        /// <summary>
        /// Invoked when a token is to be decrypted.
        /// </summary>
        public virtual Task DecryptToken(DecryptTokenContext context) => OnDecryptToken(context);

        /// <summary>
        /// Invoked when a token is to be parsed from a newly-received request.
        /// </summary>
        public virtual Task RetrieveToken(RetrieveTokenContext context) => OnRetrieveToken(context);

        /// <summary>
        /// Invoked when a token is to be validated, before final processing.
        /// </summary>
        public virtual Task ValidateToken(ValidateTokenContext context) => OnValidateToken(context);
    }
}
