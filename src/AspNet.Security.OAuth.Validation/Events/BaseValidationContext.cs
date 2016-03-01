using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using System;

namespace AspNet.Security.OAuth.Validation.Events
{
    public abstract class BaseValidationContext
    {
        public BaseValidationContext(HttpContext context, OAuthValidationOptions options)
        {
            HttpContext = context;

            if (options == null)
            {
                throw new ArgumentNullException(nameof(options));
            }
            Options = options;
        }
        public HttpContext HttpContext { get; private set; }
        public OAuthValidationOptions Options { get; }

        public EventResultState State { get; set; }

        public bool HandledResponse
        {
            get { return State == EventResultState.HandledResponse; }
        }

        public bool Skipped
        {
            get { return State == EventResultState.Skipped; }
        }

        /// <summary>
        /// Discontinue all processing for this request and return to the client.
        /// The caller is responsible for generating the full response.
        /// Set the <see cref="Ticket"/> to trigger SignIn.
        /// </summary>
        public void HandleResponse()
        {
            State = EventResultState.HandledResponse;
        }

        /// <summary>
        /// Discontinue processing the request in the current middleware and pass control to the next one.
        /// SignIn will not be called.
        /// </summary>
        public void SkipToNextMiddleware()
        {
            State = EventResultState.Skipped;
        }

        /// <summary>
        /// Gets or set the <see cref="Ticket"/> to return if this event signals it handled the event.
        /// </summary>
        public AuthenticationTicket Ticket { get; set; }
    }
}
