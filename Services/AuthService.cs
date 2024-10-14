using ms_auth.Models;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using MongoDB.Driver;

namespace ms_auth.Services
{
    public interface IAuthService
    {
        string Authenticate(UserLogin user);
        Task Register(UserRegister userRegister);
    }

    public class AuthService : IAuthService
    {
        private readonly IConfiguration _config;
        private readonly IMongoCollection<User> _usersCollection;

        public AuthService(IConfiguration config, IMongoDatabase mongoDatabase)
        {
            _config = config;
            _usersCollection = mongoDatabase.GetCollection<User>("Users");
        }

        public string Authenticate(UserLogin userLogin)
        {
            var user = _usersCollection
                .Find(u => u.Username == userLogin.Username && u.Password == userLogin.Password)
                .FirstOrDefault();

            if (user == null)
            {
                throw new UnauthorizedAccessException("Invalid username or password.");
            }

            var tokenHandler = new JwtSecurityTokenHandler();
            var jwtKey = _config["Jwt:Key"];

            if (string.IsNullOrEmpty(jwtKey))
            {
                throw new ArgumentNullException("Jwt:Key", "JWT Key cannot be null or empty.");
            }

            var key = Encoding.ASCII.GetBytes(jwtKey);

            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(new[]
                {
                    new Claim(ClaimTypes.Name, user.Username),
                    new Claim(ClaimTypes.NameIdentifier, user.Id.ToString())
                }),
                Expires = DateTime.UtcNow.AddMinutes(60),
                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature),
                Issuer = _config["Jwt:Issuer"],
                Audience = _config["Jwt:Audience"]
            };

            var token = tokenHandler.CreateToken(tokenDescriptor);

            return tokenHandler.WriteToken(token);
        }

        public async Task Register(UserRegister userRegister)
        {
            var existingUser = await _usersCollection.Find(u => u.Username == userRegister.Username).FirstOrDefaultAsync();
            if (existingUser != null)
            {
                throw new Exception("User already exists.");
            }

            var user = new User
            {
                Username = userRegister.Username,
                Password = userRegister.Password // NOTA: Es recomendable encriptar las contraseñas.
            };

            await _usersCollection.InsertOneAsync(user);
        }
    }
}
