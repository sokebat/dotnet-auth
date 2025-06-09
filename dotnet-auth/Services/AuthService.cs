// AuthService.cs
using dotnet_auth.Domain.Dto;
using dotnet_auth.Domain.Intereface;
using dotnet_auth.Domain.Model;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using System.Web;

namespace dotnet_auth.Services
{
    public class AuthService : IAuthService
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly IConfiguration _config;
        private readonly SignInManager<ApplicationUser> _signInManager;
        private readonly IHttpContextAccessor _httpContextAccessor;
        private readonly IEmailService _emailService;
        private readonly IJwtService _jwtService;

        public AuthService(
            UserManager<ApplicationUser> userManager,
            IConfiguration config,
            SignInManager<ApplicationUser> signInManager,
            IHttpContextAccessor httpContextAccessor,
            IEmailService emailService,
            IJwtService jwtService)
        {
            _userManager = userManager;
            _config = config;
            _signInManager = signInManager;
            _httpContextAccessor = httpContextAccessor;
            _emailService = emailService;
            _jwtService = jwtService;
        }

        public async Task<string> RegisterAsync(RegisterDto dto)
        {
            var existingUser = await _userManager.FindByEmailAsync(dto.Email);
            if (existingUser != null)
            {
                throw new Exception("Email is already registered.");
            }

            var user = new ApplicationUser
            {
                Email = dto.Email,
                UserName = dto.Email
            };

            var result = await _userManager.CreateAsync(user, dto.Password);
            if (!result.Succeeded)
            {
                throw new Exception(string.Join(", ", result.Errors.Select(e => e.Description)));
            }

            string token = await _userManager.GenerateEmailConfirmationTokenAsync(user);
            string encodedToken = WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(token));

            var httpContext = _httpContextAccessor.HttpContext
                ?? throw new InvalidOperationException("HttpContext is not available.");

            var request = httpContext.Request;
            string baseUrl = $"{request.Scheme}://{request.Host}";
            string verificationUrl = $"{baseUrl}/api/auth/verify-email?token={encodedToken}&email={Uri.EscapeDataString(dto.Email)}";

            var placeholders = new Dictionary<string, string>
            {
                { "VerificationLink", verificationUrl },
                { "UserName", dto.Email }
            };

            await _emailService.SendEmailAsync(
                dto.Email,
                "Confirm Your Email Address",
                "email_template.html",
                placeholders
            );

            return encodedToken;
        }

        public async Task<string> LoginAsync(LoginDto dto)
        {
            var user = await _userManager.FindByEmailAsync(dto.Email);
            if (user == null)
                throw new UnauthorizedAccessException("Invalid credentials.");

            if (!await _userManager.IsEmailConfirmedAsync(user))
                throw new UnauthorizedAccessException("Email not confirmed.");

            var result = await _signInManager.CheckPasswordSignInAsync(user, dto.Password, false);

            if (!result.Succeeded)
                throw new UnauthorizedAccessException("Invalid credentials.");

            return  _jwtService.GenerateJwtToken(user);
        }

        public async Task<(bool success, string message)> VerifyEmailAsync(string token, string email)
        {
            var user = await _userManager.FindByEmailAsync(email);
            if (user == null) return (false, "User not found.");

            var decodedToken = Encoding.UTF8.GetString(WebEncoders.Base64UrlDecode(token));
            var result = await _userManager.ConfirmEmailAsync(user, decodedToken);

            return result.Succeeded
                ? (true, "Email verified successfully.")
                : (false, "Invalid verification token.");
        }

        public async Task ForgotPasswordAsync(ForgotPasswordDto dto)
        {
            var user = await _userManager.FindByEmailAsync(dto.Email);
            if (user == null || !await _userManager.IsEmailConfirmedAsync(user))
                return;

            var token = await _userManager.GeneratePasswordResetTokenAsync(user);
            var encodedToken = WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(token));

            var httpContext = _httpContextAccessor.HttpContext
                ?? throw new InvalidOperationException("HttpContext is not available.");

            var request = httpContext.Request;
            string baseUrl = $"{request.Scheme}://{request.Host}";
            string resetUrl = $"{baseUrl}/api/auth/verify-forgot-password?token={encodedToken}&email={Uri.EscapeDataString(dto.Email)}";

            var placeholders = new Dictionary<string, string>
            {
                { "ResetPasswordLink", resetUrl },
                { "UserName", dto.Email }
            };

            await _emailService.SendEmailAsync(
                dto.Email,
                "Password Reset Request",
                "reset_password_template.html",
                placeholders
            );
        }

        public async Task<(bool success, string message)> VerifyForgotPasswordAsync(string email, string token)
        {
            var user = await _userManager.FindByEmailAsync(email);
            if (user == null) return (false, "User not found.");

            var decodedToken = Encoding.UTF8.GetString(WebEncoders.Base64UrlDecode(token));
            return await _userManager.VerifyUserTokenAsync(
                user,
                _userManager.Options.Tokens.PasswordResetTokenProvider,
                "ResetPassword",
                decodedToken
            )
                ? (true, "Token verified successfully.")
                : (false, "Invalid or expired token.");
        }

        public async Task<(bool success, string message)> ResetPasswordAsync(ResetPasswordDto dto)
        {
            var user = await _userManager.FindByEmailAsync(dto.Email);
            if (user == null) return (false, "User not found.");

            var decodedToken = Encoding.UTF8.GetString(WebEncoders.Base64UrlDecode(dto.Token));
            var result = await _userManager.ResetPasswordAsync(user, decodedToken, dto.NewPassword);

            return result.Succeeded
                ? (true, "Password reset successfully.")
                : (false, string.Join(", ", result.Errors.Select(e => e.Description)));
        }

        public Task<AuthenticationProperties> ExternalLoginAsync(string provider, string redirectUrl)
        {
            return Task.FromResult(_signInManager.ConfigureExternalAuthenticationProperties(
                provider, redirectUrl));
        }

        public async Task<(string token, bool isNewUser)> ExternalLoginCallbackAsync()
        {
            var info = await _signInManager.GetExternalLoginInfoAsync()
                ?? throw new Exception("External login info not available.");

            var result = await _signInManager.ExternalLoginSignInAsync(
                info.LoginProvider,
                info.ProviderKey,
                isPersistent: false,
                bypassTwoFactor: true);

            if (result.Succeeded)
            {
                var user = await _userManager.FindByLoginAsync(info.LoginProvider, info.ProviderKey);
                return ( _jwtService.GenerateJwtToken(user), false);
            }

            var email = info.Principal.FindFirstValue(ClaimTypes.Email)
                ?? throw new Exception("Email claim missing.");

            var existingUser = await _userManager.FindByEmailAsync(email);
            if (existingUser != null)
            {
                await _userManager.AddLoginAsync(existingUser, info);
                return (_jwtService.GenerateJwtToken(existingUser), false);
            }

            var newUser = new ApplicationUser
            {
                UserName = email,
                Email = email,
                EmailConfirmed = true
            };

            var createResult = await _userManager.CreateAsync(newUser);
            if (!createResult.Succeeded)
                throw new Exception($"User creation failed: {string.Join(", ", createResult.Errors)}");

            await _userManager.AddLoginAsync(newUser, info);
            return (_jwtService.GenerateJwtToken(newUser), true);
        }

        
    }
}