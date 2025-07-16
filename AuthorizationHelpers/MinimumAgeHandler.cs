using Microsoft.AspNetCore.Authorization;
using System.Security.Claims;

namespace JWTSelfAuth.AuthorizationHelpers
{
    public class MinimumAgeHandler : AuthorizationHandler<MinimumAgeRequirement>
    {
        protected override Task HandleRequirementAsync(AuthorizationHandlerContext context, MinimumAgeRequirement requirement)
        {
            // Get the DateOfBirth claim from the user's claims
            var dateOfBirthClaim = context.User.FindFirst(c => c.Type == ClaimTypes.DateOfBirth);

            if (dateOfBirthClaim == null)
            {
                // If DateOfBirth claim is missing, fail the requirement
                context.Fail();
                return Task.CompletedTask;
            }

            if (DateTime.TryParse(dateOfBirthClaim.Value, out DateTime dateOfBirth))
            {
                var age = DateTime.Today.Year - dateOfBirth.Year;
                if (dateOfBirth.Date > DateTime.Today.AddYears(-age)) age--; // Adjust if birthday hasn't passed this year

                if (age >= requirement.MinimumAge)
                {
                    context.Succeed(requirement); // User meets the age requirement
                }
                else
                {
                    context.Fail(); // User does not meet the age requirement
                }
            }
            else
            {
                // Claim value is not a valid date
                context.Fail();
            }

            return Task.CompletedTask;
        }
    }
}
