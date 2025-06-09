using dotnet_auth.Domain.Model;

namespace dotnet_auth.Domain.Intereface
{
    public interface IJwtService
    {
        string GenerateJwtToken(ApplicationUser user);  
    }
}
