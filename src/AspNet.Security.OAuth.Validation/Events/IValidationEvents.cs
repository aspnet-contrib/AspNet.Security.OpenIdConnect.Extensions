using System.Threading.Tasks;

namespace AspNet.Security.OAuth.Validation.Events
{
    public interface IValidationEvents
    {
        /// <summary>
        /// Invoked if exceptions are thrown during request processing. The exceptions will be re-thrown after this event unless suppressed.
        /// </summary>
        Task AuthenticationFailed(AuthenticationFailedContext context);

        /// <summary>
        /// Invoked when a protocol message is first received.
        /// </summary>
        Task ReceivingToken(ReceivingTokenContext context);
    }
}
