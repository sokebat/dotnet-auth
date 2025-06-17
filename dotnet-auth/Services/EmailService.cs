using dotnet_auth.Domain.Intereface; 
using dotnet_auth.Domain.Model;
using MailKit.Net.Smtp;
using MailKit.Security; 
using Microsoft.Extensions.Options;
using MimeKit;
 

namespace dotnet_auth.Services
{
    public class EmailService : IEmailService
    {
        private readonly EmailSettingOptions _emailSettings;
        private readonly IWebHostEnvironment _hostingEnvironment;
        private readonly ILogger<EmailService> _logger;

        public EmailService(
            IOptions<EmailSettingOptions> emailSettings,
            IWebHostEnvironment hostingEnvironment,
            ILogger<EmailService> logger)
        {
            _emailSettings = emailSettings.Value;
            _hostingEnvironment = hostingEnvironment ;
            _logger = logger;
        }

        public async Task SendEmailAsync(string toEmail, string subject, string templateFileName, Dictionary<string, string>? placeholders = null)
        {
            try
            {
            
                // Load email template
                string templatePath = Path.Combine(_hostingEnvironment.ContentRootPath, "EmailTemplates", templateFileName);
                if (!File.Exists(templatePath))
                {
                    _logger.LogError("Email template not found at path: {TemplatePath}", templatePath);
                    throw new FileNotFoundException("Email template not found.", templatePath);
                }

                string htmlBody = await File.ReadAllTextAsync(templatePath);

                // Replace placeholders in the template
                if (placeholders != null)
                {
                    foreach (var (key, value) in placeholders)
                    {
                        htmlBody = htmlBody.Replace($"{{{{{key}}}}}", value ?? string.Empty);
                    }
                }

                // Create email message
                var email = new MimeMessage();
                email.From.Add(new MailboxAddress(_emailSettings.DisplayName, _emailSettings.Mail));
                email.To.Add(MailboxAddress.Parse(toEmail));
                email.Subject = subject;

                var bodyBuilder = new BodyBuilder
                {
                    HtmlBody = htmlBody
                };
                email.Body = bodyBuilder.ToMessageBody();

                // Send email using MailKit
                using var smtp = new SmtpClient();
                await smtp.ConnectAsync(_emailSettings.Host, _emailSettings.Port);
                await smtp.AuthenticateAsync(_emailSettings.Mail, _emailSettings.Password);
                await smtp.SendAsync(email);
                await smtp.DisconnectAsync(true);

                _logger.LogInformation("Email sent successfully to {ToEmail} with subject: {Subject}", toEmail, subject);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to send email to {ToEmail} with subject: {Subject}", toEmail, subject);
                throw; // Re-throw to allow caller to handle
            }
        }
    }
}