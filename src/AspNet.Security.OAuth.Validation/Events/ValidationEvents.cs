using System;
using System.Threading.Tasks;

namespace AspNet.Security.OAuth.Validation.Events
{
    public class ValidationEvents : IValidationEvents
    {
        /// <summary>
        /// Invoked if exceptions are thrown during request processing. The exceptions will be re-thrown after this event unless suppressed.
        /// </summary>
        public Func<AuthenticationFailedContext, Task> OnAuthenticationFailed { get; set; } = context => Task.FromResult(0);

        /// <summary>
        /// Invoked when a protocol message is first received.
        /// </summary>
        public Func<ReceivingTokenContext, Task> OnReceivingToken { get; set; } = context => Task.FromResult(0);

        public Task AuthenticationFailed(AuthenticationFailedContext context) => OnAuthenticationFailed(context);

        public virtual Task ReceivingToken(ReceivingTokenContext context) => OnReceivingToken(context);
    }
}
