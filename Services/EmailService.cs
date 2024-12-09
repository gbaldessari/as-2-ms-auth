using System.Net;
using System.Net.Mail;

public class EmailService
{
    private readonly string _smtpServer;
    private readonly int _smtpPort;
    private readonly string _smtpUser;
    private readonly string _smtpPass;
    private readonly string _smtpAppName;

    public EmailService()
    {
        _smtpServer = Environment.GetEnvironmentVariable("EMAIL_SMTP_SERVER") ?? throw new ArgumentNullException("EMAIL_SMTP_SERVER");
        _smtpPort = int.TryParse(Environment.GetEnvironmentVariable("EMAIL_SMTP_PORT"), out int port) ? port : throw new ArgumentNullException("SMTP_PORT");
        _smtpUser = Environment.GetEnvironmentVariable("EMAIL_SMTP_USER") ?? throw new ArgumentNullException("EMAIL_SMTP_USER");
        _smtpPass = Environment.GetEnvironmentVariable("EMAIL_SMTP_PASSWORD") ?? throw new ArgumentNullException("EMAIL_SMTP_PASSWORD");
        _smtpAppName = Environment.GetEnvironmentVariable("EMAIL_SMTP_APP_NAME") ?? throw new ArgumentNullException("EMAIL_SMTP_APP_NAME");
    }

    public async Task SendPasswordResetEmail(string toEmail, string resetToken)
    {
        var fromAddress = new MailAddress(_smtpUser, _smtpAppName);
        var toAddress = new MailAddress(toEmail);
        const string subject = "Password Reset";
        string body = $"Usa ese token para reestablecer tu contraseña: {resetToken}";

        var smtp = new SmtpClient
        {
            Host = _smtpServer,
            Port = _smtpPort,
            EnableSsl = true,
            DeliveryMethod = SmtpDeliveryMethod.Network,
            UseDefaultCredentials = false,
            Credentials = new NetworkCredential(_smtpUser, _smtpPass)
        };

        using (var message = new MailMessage(fromAddress, toAddress)
        {
            Subject = subject,
            Body = body
        })
        {
            await smtp.SendMailAsync(message);
        }
    }
}