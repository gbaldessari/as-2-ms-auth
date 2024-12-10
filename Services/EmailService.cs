using System.Net;
using System.Net.Mail;

namespace ms_auth.Services
{
  /// <summary>
  /// Servicio para enviar correos electrónicos.
  /// </summary>
  public class EmailService
  {
    /// <summary>
    /// Servidor SMTP.
    /// </summary>
    private readonly string _smtpServer;

    /// <summary>
    /// Puerto del servidor SMTP.
    /// </summary>
    private readonly int _smtpPort;

    /// <summary>
    /// Usuario del servidor SMTP.
    /// </summary>
    private readonly string _smtpUser;

    /// <summary>
    /// Contraseña del servidor SMTP.
    /// </summary>
    private readonly string _smtpPass;

    /// <summary>
    /// Nombre de la aplicación que envía el correo.
    /// </summary>
    private readonly string _smtpAppName;

    /// <summary>
    /// Constructor que inicializa las variables de configuración del servidor SMTP desde las variables de entorno.
    /// </summary>
    /// <exception cref="ArgumentNullException">Lanzada cuando alguna variable de entorno necesaria no está definida.</exception>
    public EmailService()
    {
      _smtpServer = Environment.GetEnvironmentVariable("EMAIL_SMTP_SERVER") ?? throw new ArgumentNullException("EMAIL_SMTP_SERVER");
      _smtpPort = int.TryParse(Environment.GetEnvironmentVariable("EMAIL_SMTP_PORT"), out int port) ? port : throw new ArgumentNullException("SMTP_PORT");
      _smtpUser = Environment.GetEnvironmentVariable("EMAIL_SMTP_USER") ?? throw new ArgumentNullException("EMAIL_SMTP_USER");
      _smtpPass = Environment.GetEnvironmentVariable("EMAIL_SMTP_PASSWORD") ?? throw new ArgumentNullException("EMAIL_SMTP_PASSWORD");
      _smtpAppName = Environment.GetEnvironmentVariable("EMAIL_SMTP_APP_NAME") ?? throw new ArgumentNullException("EMAIL_SMTP_APP_NAME");
    }

    /// <summary>
    /// Envía un correo electrónico para restablecer la contraseña.
    /// </summary>
    /// <param name="toEmail">Dirección de correo electrónico del destinatario.</param>
    /// <param name="resetToken">Token de restablecimiento de contraseña.</param>
    /// <returns>Tarea asincrónica.</returns>
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

      using var message = new MailMessage(fromAddress, toAddress)
      {
        Subject = subject,
        Body = body
      };
      await smtp.SendMailAsync(message);
    }
  }
}
