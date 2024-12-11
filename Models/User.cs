using MongoDB.Bson;
using MongoDB.Bson.Serialization.Attributes;

namespace ms_auth.Models
{
  public class User
  {
    [BsonRepresentation(BsonType.String)]
    public Guid Id { get; set; }

    public required string Name { get; set; }
    public required string LastName { get; set; }
    public required string Email { get; set; }
    public required string Password { get; set; }
    public bool IsAdmin { get; set; }
    public string? Token { get; set; }
    public string? RefreshToken { get; set; }
    public DateTime? RefreshTokenExpiryTime { get; set; }
    public string? ResetPasswordToken { get; set; }
    public DateTime? ResetPasswordExpiry { get; set; }
  }

  public class UserRegister
  {
    public required string Name { get; set; }
    public required string LastName { get; set; }
    public required string Email { get; set; }
    public required string Password { get; set; }
  }

  public class UserLogin
  {
    public required string Email { get; set; }
    public required string Password { get; set; }
  }

  public class LoginResponse
  {
    public required string Token { get; set; }
    public required string RefreshToken { get; set; }
  }

  public class ForgotPasswordRequest
  {
    public required string Email { get; set; }
  }

  public class ResetPasswordRequest
  {
    public required string ResetToken { get; set; }
    public required string NewPassword { get; set; }
  }

  public class ServiceResponse<T>
  {
    public T? Data { get; set; }
    public bool Success { get; set; }
    public string? Error { get; set; }
  }
}
