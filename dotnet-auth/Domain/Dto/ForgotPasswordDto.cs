﻿namespace dotnet_auth.Domain.Dto
{
    public class ForgotPasswordDto
    {
        public string Email { get; set; } = string.Empty;
        public string Token { get; set; } = string.Empty;
        public string NewPassword { get; set; } = string.Empty;
    }

     
}
