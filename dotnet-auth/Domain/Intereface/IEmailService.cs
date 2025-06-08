namespace dotnet_auth.Domain.Intereface
{
    public interface IEmailService
    {
        Task SendEmailAsync(string toEmail, string subject, string templateFileName, Dictionary<string, string>? placeholders = null);
    }
}
