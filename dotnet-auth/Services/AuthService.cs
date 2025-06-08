using dotnet_auth.Domain.Dto;
using dotnet_auth.Domain.Intereface;
using dotnet_auth.Domain.Model;
using Microsoft.AspNetCore.Identity;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
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



        public AuthService(UserManager<ApplicationUser> userManager, IConfiguration config, SignInManager<ApplicationUser> signInManager, IConfiguration configuration, IHttpContextAccessor httpContextAccessor, IEmailService emailService)
        {
            _userManager = userManager;
            _config = config;
            _signInManager = signInManager;
            _httpContextAccessor = httpContextAccessor;
            _emailService = emailService;
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
                throw new Exception("Registration Failed");
            }

            // Generate token
            string token = await _userManager.GenerateEmailConfirmationTokenAsync(user);
            string encodedToken = Uri.EscapeDataString(token);

            // Safely access HttpContext
            var httpContext = _httpContextAccessor.HttpContext;
            if (httpContext == null)
            {
                throw new InvalidOperationException("HttpContext is not available.");
            }

            var request = httpContext.Request;
            string baseUrl = $"{request.Scheme}://{request.Host}";
            string verificationUrl = $"{baseUrl}/Auth/verify-email?token={encodedToken}&email={HttpUtility.UrlEncode(dto.Email)}";
            // Prepare email
            string subject = "Confirm Your Email Address";
            var placeholders = new Dictionary<string, string>
                {
                    { "VerificationLink", verificationUrl },
                    { "UserName", dto.Email }
                };

            // Send email
            await _emailService.SendEmailAsync(
                dto.Email,
                subject,
                "email_template.html",
                placeholders
            );

            //_logger.LogInformation("Registration successful for email: {Email}. Verification email sent.", dto.Email);


            return token;
        }

        public async Task<string> LoginAsync(LoginDto dto)
        {
            var user = await _userManager.FindByEmailAsync(dto.Email);
            if (user == null)
                throw new Exception("User not found.");

            SignInResult result = await _signInManager.PasswordSignInAsync(user, dto.Password, false, false);

            if (result.Succeeded)
            {
                var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_config["Jwt:Key"]!));
                var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

                var token = new JwtSecurityToken(
                    issuer: _config["Jwt:Issuer"],
                    audience: _config["Jwt:Audience"],
                    expires: DateTime.UtcNow.AddDays(1),
                    signingCredentials: creds
                );

                return new JwtSecurityTokenHandler().WriteToken(token);
            }


            return "Login failed. Please check your credentials.";

        }


        public async Task<(bool success, string message)> VerifyEmailAsync(string token, string email)
        {
            var user = await _userManager.FindByEmailAsync(email);
            if (user == null)
            {
                return (false, "User not found.");
            }

            var result = await _userManager.ConfirmEmailAsync(user, token);
            if (!result.Succeeded)
            {
                return (false, "Email verification failed. Please try again.");
            }

            return (true, "Email verified successfully.");
        }


        public async Task ForgotPasswordAsync(ForgotPasswordDto dto)
        {
            var user = await _userManager.FindByEmailAsync(dto.Email);
            if (user == null)
            {
                // Don't reveal user doesn't exist for security
                return;
            }

            // Generate password reset token
            var token = await _userManager.GeneratePasswordResetTokenAsync(user);
            var encodedToken = Uri.EscapeDataString(token);

            // Build reset verification URL
            var httpContext = _httpContextAccessor.HttpContext ?? throw new InvalidOperationException("HttpContext is not available.");
            var request = httpContext.Request;
            string baseUrl = $"{request.Scheme}://{request.Host}";
            string resetUrl = $"{baseUrl}/api/auth/verify-reset-password-token?token={encodedToken}&email={HttpUtility.UrlEncode(dto.Email)}";

            // Send password reset verification email
            var placeholders = new Dictionary<string, string>
        {
            { "ResetPasswordLink", resetUrl },
            { "UserName", dto.Email }
        };
            await _emailService.SendEmailAsync(dto.Email, "Verify Your Password Reset Request", "reset_password_template.html", placeholders);
        }

        public async Task<(bool success, string message)> VerifyForgotPasswordAsync(string Email, string Token)
        {
            var user = await _userManager.FindByEmailAsync(Email);
            if (user == null)
            {
                return (false, "User not found.");
            }

            // Verify the token is valid
            var isValid = await _userManager.VerifyUserTokenAsync(
                user,
                _userManager.Options.Tokens.PasswordResetTokenProvider,
                "ResetPassword",
                Uri.UnescapeDataString(Token)
            );

            if (!isValid)
            {
                return (false, "Invalid or expired reset token.");
            }

            return (true, "Reset token verified successfully. You can now reset your password.");
        }


        public async Task<(bool success, string message)> ResetPasswordAsync(ResetPasswordDto dto)
        {
            var user = await _userManager.FindByEmailAsync(dto.Email);
            if (user == null)
            {
                return (false, "User not found.");
            }

            // Reset the password using the provided token and new password
            var result = await _userManager.ResetPasswordAsync(
                user,
                Uri.UnescapeDataString(dto.Token),
                dto.NewPassword
            );

            if (result.Succeeded)
            {
                return (true, "Password reset successfully.");
            }

            // Aggregate errors if the reset fails
            var errors = string.Join(", ", result.Errors.Select(e => e.Description));
            return (false, $"Failed to reset password: {errors}");
        }

    }

}
