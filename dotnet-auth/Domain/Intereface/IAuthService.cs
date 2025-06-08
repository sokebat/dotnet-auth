using dotnet_auth.Domain.Dto;

namespace dotnet_auth.Domain.Intereface
{
    public interface IAuthService
    {
        Task<string> RegisterAsync(RegisterDto dto);
        Task<string> LoginAsync(LoginDto dto);
        Task<(bool success, string message)> VerifyEmailAsync(string token, string email);

    }
}
