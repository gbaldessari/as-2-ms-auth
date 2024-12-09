using Microsoft.AspNetCore.Mvc;
using ms_auth.Models;
using ms_auth.Services;

namespace ms_auth.Controllers
{
    [ApiController]
    [Route("[controller]")]
    public class AuthController(IAuthService authService, RabbitMQClient rabbitMQClient) : ControllerBase
    {
        private readonly IAuthService _authService = authService;
        private readonly RabbitMQClient _rabbitMQClient = rabbitMQClient;

        [HttpPost("login")]
        public async Task<IActionResult> Login(UserLogin userLogin)
        {
            LoginResult tokens = await _authService.Authenticate(userLogin);
            if (tokens == null) return Unauthorized();
            _rabbitMQClient.Publish("User logged in: " + userLogin.Email);
            return Ok(tokens);
        }

        [HttpPost("register")]
        public async Task<IActionResult> Register([FromBody] UserRegister userRegister)
        {
            try
            {
                await _authService.Register(userRegister);
                _rabbitMQClient.Publish("User registered: " + userRegister.Email);
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
                _rabbitMQClient.Publish("Token refreshed for: " + refreshToken);
                return Ok(payload);
            }
            catch (Exception ex)
            {
                return BadRequest(new { ex.Message });
            }
        }

        [HttpPost("forgot-password")]
        public async Task<IActionResult> ForgotPassword([FromBody] ForgotPasswordRequest request)
        {
            if (string.IsNullOrEmpty(request.Email))
            {
                return BadRequest("Email is required.");
            }

            try
            {
                await _authService.ForgotPassword(request.Email);
                return Ok("Password reset token sent to email.");
            }
            catch (InvalidOperationException ex)
            {
                return BadRequest(ex.Message);
            }
        }

        [HttpPost("reset-password")]
        public async Task<IActionResult> ResetPassword([FromBody] ResetPasswordRequest request)
        {
            if (string.IsNullOrEmpty(request.ResetToken) || string.IsNullOrEmpty(request.NewPassword))
            {
                return BadRequest("Reset token and new password are required.");
            }

            try
            {
                await _authService.ResetPassword(request.ResetToken, request.NewPassword);
                return Ok("Password has been reset.");
            }
            catch (InvalidOperationException ex)
            {
                return BadRequest(ex.Message);
            }
        }
    }
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
