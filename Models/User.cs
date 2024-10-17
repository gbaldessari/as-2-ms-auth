namespace ms_auth.Models {
  public class User {
    public Guid Id { get; set; }
    public required string Username { get; set; }
    public required string Password { get; set; }
    public string? Token { get; set; }
    public string? RefreshToken { get; set; }
    public DateTime? RefreshTokenExpiryTime { get; set; }
  }

  public class UserRegister {
    public required string Username { get; set; }
    public required string Password { get; set; }
  }

  public class UserLogin {
    public required string Username { get; set; }
    public required string Password { get; set; }
  }

  public class Tokens {
    public string? Token { get; set; }
    public string? RefreshToken { get; set; }
  }
}
