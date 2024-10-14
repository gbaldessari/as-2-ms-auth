namespace ms_auth.Models
{
    public class User
  {
    public string Id { get; set; }
    public required string Username { get; set; }
    public required string Password { get; set; }
  }
  
  public class UserRegister
  {
    public required string Username { get; set; }
    public required string Password { get; set; }
  }

  public class UserLogin
  {
    public required string Username { get; set; }
    public required string Password { get; set; }
  }
}
