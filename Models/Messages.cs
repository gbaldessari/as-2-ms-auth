namespace ms_auth.Models
{
  /// <summary>
  /// Interfaz para procesar mensajes.
  /// </summary>
  public interface IMessageProcessor
  {
    /// <summary>
    /// Procesa un mensaje dado.
    /// </summary>
    /// <param name="message">El mensaje a procesar.</param>
    Task ProcessMessage(string message);
  }

  /// <summary>
  /// Representa un mensaje de usuario.
  /// </summary>
  public class UserMessage
  {
    /// <summary>
    /// Patrón del mensaje.
    /// </summary>
    public required Pattern Pattern { get; set; }

    /// <summary>
    /// Datos del mensaje.
    /// </summary>
    public required RegisterData Data { get; set; }

    /// <summary>
    /// Identificador del mensaje.
    /// </summary>
    public required string Id { get; set; }
  }

  /// <summary>
  /// Representa un patrón de mensaje.
  /// </summary>
  public class Pattern
  {
    /// <summary>
    /// Comando del patrón.
    /// </summary>
    public required string Cmd { get; set; }
  }

  /// <summary>
  /// Representa los datos de un mensaje.
  /// </summary>
  public class RegisterData
  {
    /// <summary>
    /// Correo electrónico del usuario.
    /// </summary>
    public required string Email { get; set; }

    /// <summary>
    /// Contraseña del usuario.
    /// </summary>
    public required string Password { get; set; }

    /// <summary>
    /// Nombre del usuario.
    /// </summary>
    public required string Name { get; set; }

    /// <summary>
    /// Apellido del usuario.
    /// </summary>
    public required string LastName { get; set; }
  }

  /// <summary>
  /// Representa el resultado de un inicio de sesión.
  /// </summary>
  public class LoginResult
  {
    /// <summary>
    /// Token de autenticación.
    /// </summary>
    public required string Token { get; set; }

    /// <summary>
    /// Token de actualización.
    /// </summary>
    public required string RefreshToken { get; set; }
  }
}