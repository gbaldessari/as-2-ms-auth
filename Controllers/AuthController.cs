using Microsoft.AspNetCore.Mvc;
using ms_auth.Models;
using ms_auth.Services;

namespace ms_auth.Controllers
{
    [ApiController]
    [Route("[controller]")]
    public class AuthController(IAuthService authService) : ControllerBase
    {
        private readonly IAuthService _authService = authService;

        [HttpPost("login")]
        public IActionResult Login(UserLogin userLogin)
        {
            Tokens tokens = _authService.Authenticate(userLogin);
            if (tokens == null) return Unauthorized();
            return Ok(tokens);
        }

        [HttpPost("register")]
        public async Task<IActionResult> Register(UserRegister userRegister)
        {
            try
            {
                await _authService.Register(userRegister);
                return Ok("User registered successfully.");
            }
            catch (Exception ex)
            {
                return BadRequest(new { ex.Message });
            }
        }

        [HttpPost("refresh-token")]
        public IActionResult RefreshToken(string refreshToken)
        {
            try
            {
                var payload = _authService.RefreshToken(refreshToken);
                return Ok(payload);
            }
            catch (Exception ex)
            {
                return BadRequest(new { ex.Message });
            }
        }
    }
}
