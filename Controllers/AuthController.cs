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

        [HttpGet("login")]
        public IActionResult Login(UserLogin userLogin)
        {
            Response tokens = _authService.Authenticate(userLogin);
            if (tokens == null) return Unauthorized();
            return Ok(tokens);
        }

        [HttpPost("register")]
        public async Task<IActionResult> Register([FromBody] UserRegister userRegister)
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

        [HttpGet("refresh-token")]
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
