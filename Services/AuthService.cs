using ms_auth.Models;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace ms_auth.Services
{
  public interface IAuthService
  {
    string Authenticate(UserLogin user);
  }

  public class AuthService(IConfiguration config) : IAuthService
  {
    private readonly IConfiguration _config = config;
    private readonly List<User> users =
        [
            new() { Id = 1, Username = "test", Password = "password" }
        ];

    public string Authenticate(UserLogin userLogin)
    {
      var user = users.SingleOrDefault(x => x.Username == userLogin.Username && x.Password == userLogin.Password);
      if (user == null) return null;

      var tokenHandler = new JwtSecurityTokenHandler();
      var jwtKey = _config["Jwt:Key"];
      if (string.IsNullOrEmpty(jwtKey))
      {
        throw new ArgumentNullException("Jwt:Key", "JWT Key cannot be null or empty.");
      }
      var key = Encoding.ASCII.GetBytes(jwtKey);

      var tokenDescriptor = new SecurityTokenDescriptor
      {
        Subject = new ClaimsIdentity(
          [
            new Claim(ClaimTypes.Name, user.Username),
          ]),
        Expires = DateTime.UtcNow.AddMinutes(60),
        SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature),
        Issuer = _config["Jwt:Issuer"],
        Audience = _config["Jwt:Audience"]
      };

      var token = tokenHandler.CreateToken(tokenDescriptor);
      return tokenHandler.WriteToken(token);
    }
  }
}
