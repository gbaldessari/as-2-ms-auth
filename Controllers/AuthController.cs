using Microsoft.AspNetCore.Mvc;
using ms_auth.Models;
using ms_auth.Services;

namespace ms_auth.Controllers
{
  [ApiController]
  [Route("[controller]")]
  public class AuthController : ControllerBase
  {
    private readonly IAuthService _authService;

    public AuthController(IAuthService authService)
    {
      _authService = authService;
    }

    [HttpPost("login")]
    public async Task<IActionResult> Login(UserLogin userLogin)
    {
      try
      {
        LoginResult tokens = await _authService.Authenticate(userLogin);
        if (tokens == null) return Unauthorized();
        return Ok(tokens);
      }
      catch (UnauthorizedAccessException)
      {
        return Unauthorized();
      }
      catch (Exception ex)
      {
        return BadRequest(new { ex.Message });
      }
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

    [HttpPost("refresh-token")]
    public async Task<IActionResult> RefreshToken(string refreshToken)
    {
      try
      {
        var payload = await _authService.RefreshToken(refreshToken);
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
