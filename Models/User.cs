using MongoDB.Bson;
using MongoDB.Bson.Serialization.Attributes;

namespace ms_auth.Models
{
  /// <summary>
  /// Representa un usuario en el sistema.
  /// </summary>
  public class User
  {
    /// <summary>
    /// Identificador único del usuario.
    /// </summary>
    [BsonRepresentation(BsonType.String)]
    public Guid Id { get; set; }

    /// <summary>
    /// Nombre del usuario.
    /// </summary>
    public required string Name { get; set; }

    /// <summary>
    /// Apellido del usuario.
    /// </summary>
    public required string LastName { get; set; }

    /// <summary>
    /// Correo electrónico del usuario.
    /// </summary>
    public required string Email { get; set; }

    /// <summary>
    /// Contraseña del usuario.
    /// </summary>
    public required string Password { get; set; }

    /// <summary>
    /// Indica si el usuario tiene privilegios de administrador.
    /// </summary>
    public bool IsAdmin { get; set; }

    /// <summary>
    /// Token de autenticación del usuario.
    /// </summary>
    public string? Token { get; set; }

    /// <summary>
    /// Token de actualización del usuario.
    /// </summary>
    public string? RefreshToken { get; set; }

    /// <summary>
    /// Fecha y hora de expiración del token de actualización.
    /// </summary>
    public DateTime? RefreshTokenExpiryTime { get; set; }

    /// <summary>
    /// Token para restablecer la contraseña del usuario.
    /// </summary>
    public string? ResetPasswordToken { get; set; }

    /// <summary>
    /// Fecha y hora de expiración del token para restablecer la contraseña.
    /// </summary>
    public DateTime? ResetPasswordExpiry { get; set; }
  }

  /// <summary>
  /// Representa los datos necesarios para registrar un nuevo usuario.
  /// </summary>
  public class UserRegister
  {
    /// <summary>
    /// Nombre del usuario.
    /// </summary>
    public required string Name { get; set; }

    /// <summary>
    /// Apellido del usuario.
    /// </summary>
    public required string LastName { get; set; }

    /// <summary>
    /// Correo electrónico del usuario.
    /// </summary>
    public required string Email { get; set; }

    /// <summary>
    /// Contraseña del usuario.
    /// </summary>
    public required string Password { get; set; }
  }

  /// <summary>
  /// Representa los datos necesarios para iniciar sesión.
  /// </summary>
  public class UserLogin
  {
    /// <summary>
    /// Correo electrónico del usuario.
    /// </summary>
    public required string Email { get; set; }

    /// <summary>
    /// Contraseña del usuario.
    /// </summary>
    public required string Password { get; set; }
  }

  /// <summary>
  /// Representa la respuesta de autenticación.
  /// </summary>
  public class Response
  {
    /// <summary>
    /// Token de autenticación.
    /// </summary>
    public string? Token { get; set; }

    /// <summary>
    /// Token de actualización.
    /// </summary>
    public string? RefreshToken { get; set; }
  }

  /// <summary>
  /// Modelo para la solicitud de restablecimiento de contraseña.
  /// </summary>
  public class ForgotPasswordRequest
  {
    /// <summary>
    /// Correo electrónico del usuario.
    /// </summary>
    public required string Email { get; set; }
  }

  /// <summary>
  /// Modelo para la solicitud de restablecimiento de contraseña.
  /// </summary>
  public class ResetPasswordRequest
  {
    /// <summary>
    /// Token de restablecimiento de contraseña.
    /// </summary>
    public required string ResetToken { get; set; }

    /// <summary>
    /// Nueva contraseña del usuario.
    /// </summary>
    public required string NewPassword { get; set; }
  }
}
