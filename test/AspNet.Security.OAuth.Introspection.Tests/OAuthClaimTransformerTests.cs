using System;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using Xunit;

namespace AspNet.Security.OAuth.Introspection.Tests
{
    public class OAuthClaimTransformerTests
    {
        private readonly Uri claimsIssuer = new Uri("http://issuer.com/");
        private readonly string schema = "any";
        [Fact]
        public async Task When_ClaimIssuer_Is_Set_TransformWithIssuer()
        {
            var sut = CreateSut(schema, claimsIssuer);
            var incommingClaim = new Claim(ClaimTypes.Name,"Test Smith");
            var actual = await sut.TransformAsync(new ClaimsPrincipal(new AlwaysAuthneticatedUser(schema,incommingClaim)));

            Assert.Contains(actual.Claims, claim => 
                claim.Value == incommingClaim.Value 
                && claim.Type == incommingClaim.Type
                && claim.Issuer == claimsIssuer.ToString());
        }
        [Fact]
        public async Task When_ClaimIssuer_Is_Set_And_Other_Schema_Do_Not_Tranform()
        {
            var sut = CreateSut(schema, claimsIssuer);
            var incommingClaim = new Claim(ClaimTypes.Name, "Test Smith");

            var actual = await sut.TransformAsync(new ClaimsPrincipal(new AlwaysAuthneticatedUser("otherSchema", incommingClaim)));

            Assert.DoesNotContain(actual.Claims, claim =>
                claim.Value == incommingClaim.Value
                && claim.Type == incommingClaim.Type
                && claim.Issuer == claimsIssuer.ToString());
        }
        private static OAuthClaimTransformer CreateSut(string schema, Uri claimsIssuer) =>
            new OAuthClaimTransformer(schema, new OAuthIntrospectionOptions
        {
            ClaimsIssuer =  claimsIssuer?.ToString(),
            Authority = claimsIssuer
        });

        internal class AlwaysAuthneticatedUser: ClaimsIdentity
        {
            public AlwaysAuthneticatedUser(string authenticationType ,params Claim[] claims):base(claims)
            {
                AuthenticationType = authenticationType;
            }

            public override string AuthenticationType { get; }

            public override bool IsAuthenticated => true;
        }
    }
}
