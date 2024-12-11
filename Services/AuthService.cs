using ms_auth.Models;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using MongoDB.Driver;
using System.Security.Cryptography;

namespace ms_auth.Services
{
  public interface IAuthService
  {
    Task<ServiceResponse<LoginResponse>> RefreshToken(string refreshToken);
    Task<ServiceResponse<LoginResponse>> Authenticate(UserLogin userLogin);
    Task<ServiceResponse<string>> Register(UserRegister userRegister);
    Task<ServiceResponse<string>> ForgotPassword(string email);
    Task<ServiceResponse<string>> ResetPassword(string resetToken, string newPassword);
  }

  public class AuthService : IAuthService
  {
    private readonly IConfiguration _config;
    private readonly IMongoCollection<User> _usersCollection;

    public AuthService(IConfiguration config, IMongoDatabase mongoDatabase)
    {
      _config = config ?? throw new ArgumentNullException(nameof(config));
      _usersCollection = mongoDatabase.GetCollection<User>("users");
    }

    public async Task<ServiceResponse<LoginResponse>> Authenticate(UserLogin userLogin)
    {
      var response = new ServiceResponse<LoginResponse>();
      try
      {
        var user = await _usersCollection
            .Find(u => u.Email == userLogin.Email)
            .FirstOrDefaultAsync();

        if (user == null || !BCrypt.Net.BCrypt.Verify(userLogin.Password, user.Password))
        {
          response.Success = false;
          response.Error = "Invalid username or password.";
          return response;
        }

        var tokenHandler = new JwtSecurityTokenHandler();
        var jwtKey = _config["Jwt:Key"];
        if (string.IsNullOrEmpty(jwtKey))
        {
          throw new ArgumentNullException(nameof(jwtKey), "JWT key cannot be null or empty.");
        }
        var key = Encoding.ASCII.GetBytes(jwtKey);

        var tokenDescriptor = new SecurityTokenDescriptor
        {
          Subject = new ClaimsIdentity(
            [
                new Claim(ClaimTypes.Name, user.Email),
                new Claim(ClaimTypes.NameIdentifier, user.Id.ToString())
            ]),
          Expires = DateTime.UtcNow.AddMinutes(60),
          SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature),
          Issuer = _config["Jwt:Issuer"],
          Audience = _config["Jwt:Audience"]
        };

        var token = tokenHandler.CreateToken(tokenDescriptor);
        var jwtToken = tokenHandler.WriteToken(token);

        var refreshToken = GenerateRefreshToken();
        user.Token = jwtToken;
        user.RefreshToken = refreshToken;
        user.RefreshTokenExpiryTime = DateTime.UtcNow.AddDays(7);

        _usersCollection.ReplaceOne(u => u.Id == user.Id, user);

        response.Data = new LoginResponse { Token = jwtToken, RefreshToken = refreshToken };
        response.Success = true;
      }
      catch (Exception ex)
      {
        response.Success = false;
        response.Error = ex.Message;
      }
      return response;
    }

    public async Task<ServiceResponse<string>> Register(UserRegister userRegister)
    {
      var response = new ServiceResponse<string>();
      try
      {
        var existingUser = await _usersCollection.Find(u => u.Email == userRegister.Email).FirstOrDefaultAsync();
        if (existingUser != null)
        {
          response.Success = false;
          response.Error = "User already exists.";
          return response;
        }

        var newUser = new User
        {
          Id = Guid.NewGuid(),
          Name = userRegister.Name,
          LastName = userRegister.LastName,
          Email = userRegister.Email,
          Password = BCrypt.Net.BCrypt.HashPassword(userRegister.Password),
          IsAdmin = false,
          Token = null,
          RefreshToken = null,
          RefreshTokenExpiryTime = null
        };

        await _usersCollection.InsertOneAsync(newUser);
        response.Data = "User registered successfully.";
        response.Success = true;
      }
      catch (Exception ex)
      {
        response.Success = false;
        response.Error = ex.Message;
      }
      return response;
    }

    public async Task<ServiceResponse<LoginResponse>> RefreshToken(string refreshToken)
    {
      var response = new ServiceResponse<LoginResponse>();
      try
      {
        var user = _usersCollection
        .Find(u => u.RefreshToken == refreshToken && u.RefreshTokenExpiryTime > DateTime.UtcNow)
        .FirstOrDefault() ?? throw new Exception("Invalid refresh token.");

        var loginResult = await Authenticate(new UserLogin { Email = user.Email, Password = user.Password });
        if (loginResult.Data == null)
        {
          throw new InvalidOperationException("Login result data is null.");
        }
        var obj = new LoginResponse { Token = loginResult.Data.Token, RefreshToken = loginResult.Data.RefreshToken };
        string newToken = obj.Token ?? throw new InvalidOperationException("Token generation failed.");
        var newRefreshToken = GenerateRefreshToken();
        user.Token = newToken;
        user.RefreshToken = newRefreshToken;
        user.RefreshTokenExpiryTime = DateTime.UtcNow.AddDays(7);

        await _usersCollection.ReplaceOneAsync(u => u.Id == user.Id, user);
        response.Data = new LoginResponse { Token = newToken, RefreshToken = newRefreshToken };
        response.Success = true;
      }
      catch (Exception ex)
      {
        response.Success = false;
        response.Error = ex.Message;
      }
      return response;
    }

    public string GenerateRefreshToken()
    {
      var randomBytes = new byte[64];
      using var rng = RandomNumberGenerator.Create();
      rng.GetBytes(randomBytes);
      return Convert.ToBase64String(randomBytes);
    }

    public async Task<ServiceResponse<string>> ForgotPassword(string email)
    {
      var response = new ServiceResponse<string>();
      try
      {
        var user = await _usersCollection.Find(u => u.Email == email).FirstOrDefaultAsync();
        if (user == null)
        {
          response.Success = false;
          response.Error = "User does not exist.";
          return response;
        }

        var resetToken = Guid.NewGuid().ToString();
        user.ResetPasswordToken = resetToken;
        user.ResetPasswordExpiry = DateTime.UtcNow.AddHours(1);

        await _usersCollection.ReplaceOneAsync(u => u.Id == user.Id, user);

        var emailService = new EmailService();
        await emailService.SendPasswordResetEmail(user.Email, resetToken);

        response.Data = "Password reset email sent.";
        response.Success = true;
      }
      catch (Exception ex)
      {
        response.Success = false;
        response.Error = ex.Message;
      }
      return response;
    }

    public async Task<ServiceResponse<string>> ResetPassword(string resetToken, string newPassword)
    {
      var response = new ServiceResponse<string>();
      try
      {
        var user = await _usersCollection.Find(u => u.ResetPasswordToken == resetToken && u.ResetPasswordExpiry > DateTime.UtcNow).FirstOrDefaultAsync();
        if (user == null)
        {
          response.Success = false;
          response.Error = "Invalid or expired password reset token.";
          return response;
        }

        user.Password = BCrypt.Net.BCrypt.HashPassword(newPassword);
        user.ResetPasswordToken = null;
        user.ResetPasswordExpiry = null;

        await _usersCollection.ReplaceOneAsync(u => u.Id == user.Id, user);
        response.Data = "Password reset successfully.";
        response.Success = true;
      }
      catch (Exception ex)
      {
        response.Success = false;
        response.Error = ex.Message;
      }
      return response;
    }
  }
}
