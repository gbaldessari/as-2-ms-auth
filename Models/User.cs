using MongoDB.Bson;
using MongoDB.Bson.Serialization.Attributes;

namespace ms_auth.Models {
  public class User {
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
  }

  public class UserRegister {
    public required string Name { get; set; }
    public required string LastName { get; set; }
    public required string Email { get; set; }
    public required string Password { get; set; }
  }

  public class UserLogin {
    public required string Email { get; set; }
    public required string Password { get; set; }
  }

  public class Response {
    public string? Token { get; set; }
    public string? RefreshToken { get; set; }
  }
}
