using dotnet_auth.Domain.Dto;
using dotnet_auth.Domain.Intereface;
using Microsoft.AspNetCore.Mvc;

[ApiController]
[Route("api/[controller]")]
public class AuthController : ControllerBase
{
    private readonly IAuthService _authService;

    public AuthController(IAuthService authService)
    {
        _authService = authService;
    }

    [HttpPost("register")]
    public async Task<IActionResult> Register(RegisterDto dto)
    {
        try
        {
            var token = await _authService.RegisterAsync(dto);
            return Ok(new
            {
                success = true,
                message = "Registration successful. Please verify your email.",
                data = new { verificationToken = token }
            });
        }
        catch (Exception ex)
        {
            return BadRequest(new { success = false, message = ex.Message });
        }
    }

    [HttpPost("login")]
    public async Task<IActionResult> Login(LoginDto dto)
    {
        try
        {
            var token = await _authService.LoginAsync(dto);
            return Ok(new
            {
                success = true,
                message = "Login successful.",
                data = new { token }
            });
        }
        catch (UnauthorizedAccessException ex)
        {
            return Unauthorized(new { success = false, message = ex.Message });
        }
        catch (Exception ex)
        {
            return BadRequest(new { success = false, message = ex.Message });
        }
    }

    [HttpGet("verify-email")]
    public async Task<IActionResult> VerifyEmail(string token, string email)
    {
        if (string.IsNullOrEmpty(token) || string.IsNullOrEmpty(email))
        {
            return BadRequest(new { success = false, message = "Token and email are required." });
        }

        var result = await _authService.VerifyEmailAsync(token, email);
        if (result.success)
        {
            return Ok(new { success = true, message = result.message });
        }
        else
        {
            return BadRequest(new { success = false, message = result.message });
        }
    }

    [HttpPost("forgot-password")]
    public async Task<IActionResult> ForgotPassword(ForgotPasswordDto dto)
    {
        try
        {
            await _authService.ForgotPasswordAsync(dto);
            return Ok(new
            {
                success = true,
                message = "Password reset email sent successfully."
            });
        }
        catch (Exception ex)
        {
            return BadRequest(new { success = false, message = ex.Message });
        }
    }

    [HttpGet("verify-forgot-password")]
    public async Task<IActionResult> VerifyForgotPassword(string email, string token)
    {
        if (string.IsNullOrEmpty(email) || string.IsNullOrEmpty(token))
        {
            return BadRequest(new { success = false, message = "Email and token are required." });
        }
        var result = await _authService.VerifyForgotPasswordAsync(email, token);
        if (result.success)
        {
            return Ok(new { success = true, message = result.message });
        }
        else
        {
            return BadRequest(new { success = false, message = result.message });
        }
    }

    [HttpPost("reset-password")]
    public async Task<IActionResult> ResetPassword(ResetPasswordDto dto)
    {
        if (string.IsNullOrEmpty(dto.Email) || string.IsNullOrEmpty(dto.Token) || string.IsNullOrEmpty(dto.NewPassword))
        {
            return BadRequest(new { success = false, message = "Email, token, and new password are required." });
        }

        try
        {
            var result = await _authService.ResetPasswordAsync(dto);
            if (result.success)
            {
                return Ok(new { success = true, message = result.message });
            }
            return BadRequest(new { success = false, message = result.message });
        }
        catch (Exception ex)
        {
            return BadRequest(new { success = false, message = ex.Message });
        }
    }

}
