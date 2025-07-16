using Microsoft.AspNetCore.Authorization;

namespace JWTSelfAuth.AuthorizationHelpers
{
    public class MinimumAgeRequirement : IAuthorizationRequirement
    {
        public int MinimumAge { get; }

        public MinimumAgeRequirement(int minimumAge)
        {
            MinimumAge = minimumAge;
        }
    }
}
