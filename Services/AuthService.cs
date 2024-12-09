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
        Response RefreshToken(string refreshToken);
        Task<LoginResult> Authenticate(UserLogin userLogin);
        Task Register(UserRegister userRegister);
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

        public Response Authenticate(UserLogin userLogin)
        {
            var user = _usersCollection
                .Find(u => u.Email == userLogin.Email)
                .FirstOrDefault();

            if (user == null || !BCrypt.Net.BCrypt.Verify(userLogin.Password, user.Password))
            {
                throw new UnauthorizedAccessException("Invalid username or password.");
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

            return new Response { Token = jwtToken, RefreshToken = refreshToken };
        }

        public async Task Register(UserRegister userRegister)
        {
            // Verificar si el usuario ya existe
            var existingUser = await _usersCollection.Find(u => u.Email == userRegister.Email).FirstOrDefaultAsync();
            if (existingUser != null)
            {
                throw new InvalidOperationException("User already exists.");
            }

            // Crear un nuevo usuario
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

            // Insertar el nuevo usuario en la colección
            await _usersCollection.InsertOneAsync(newUser);
        }

        public Response RefreshToken(string refreshToken)
        {
            var user = _usersCollection
            .Find(u => u.RefreshToken == refreshToken && u.RefreshTokenExpiryTime > DateTime.UtcNow)
            .FirstOrDefault() ?? throw new Exception("Invalid refresh token.");

            Response obj = Authenticate(new UserLogin { Email = user.Email, Password = user.Password });
            string newToken = obj.Token ?? throw new InvalidOperationException("Token generation failed.");
            var newRefreshToken = GenerateRefreshToken();
            user.Token = newToken;
            user.RefreshToken = newRefreshToken;
            user.RefreshTokenExpiryTime = DateTime.UtcNow.AddDays(7);

            _usersCollection.ReplaceOne(u => u.Id == user.Id, user);
            return new Response { Token = newToken, RefreshToken = newRefreshToken };
        }

        public string GenerateRefreshToken()
        {
            var randomBytes = new byte[64];
            using var rng = RandomNumberGenerator.Create();
            rng.GetBytes(randomBytes);
            return Convert.ToBase64String(randomBytes);
        }

        Task<LoginResult> IAuthService.Authenticate(UserLogin userLogin)
        {
            throw new NotImplementedException();
        }
    }
}
