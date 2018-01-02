using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;

namespace AspNet.Security.OAuth.Introspection
{
    public class OAuthClaimsTransformer : IClaimsTransformation
    {
        private readonly string _schema;
        private readonly OAuthIntrospectionOptions _options;

        public OAuthClaimsTransformer(string schema, OAuthIntrospectionOptions options)
        {
            _schema = schema;
            _options = options;
        }
        public Task<ClaimsPrincipal> TransformAsync(ClaimsPrincipal principal)
        {
            if (!principal.Identity.IsAuthenticated || principal.Identity.AuthenticationType != _schema)
                return Task.FromResult(principal);

            var id = (ClaimsIdentity)principal.Identity;
            var transformedClaims = TransformedClaimsWithCurityIssuer(id);
            var ci = new ClaimsIdentity(transformedClaims, id.AuthenticationType, id.NameClaimType, id.RoleClaimType);

            return Task.FromResult(new ClaimsPrincipal(ci));
        }

        private IEnumerable<Claim> TransformedClaimsWithCurityIssuer(ClaimsIdentity id)
        {
            var transformedClaims = id.Claims.Select(x =>
                new Claim(x.Type, x.Value, x.ValueType, _options.Authority.ToString(), x.Issuer));
            return transformedClaims;
        }
    }
}
