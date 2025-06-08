using dotnet_auth.Domain.Dto;

namespace dotnet_auth.Domain.Intereface
{
    public interface IAuthService
    {
        Task<string> RegisterAsync(RegisterDto dto);
        Task<string> LoginAsync(LoginDto dto);
        Task ForgotPasswordAsync(ForgotPasswordDto dto);
        Task<(bool success, string message)> ResetPasswordAsync(ResetPasswordDto dto);
        Task<(bool success, string message)> VerifyEmailAsync(string token, string email);
        Task<(bool success, string message)> VerifyForgotPasswordAsync(string Email, string Token);

    }
}
