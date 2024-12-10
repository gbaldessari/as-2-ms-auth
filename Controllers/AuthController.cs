using Microsoft.AspNetCore.Mvc;
using ms_auth.Models;
using ms_auth.RabbitMQ;
using ms_auth.Services;

namespace ms_auth.Controllers
{
  /// <summary>
  /// Controlador para la autenticación de usuarios.
  /// </summary>
  [ApiController]
  [Route("[controller]")]
  public class AuthController(IAuthService authService, IRabbitMQClient rabbitMQClient) : ControllerBase
  {
    private readonly IAuthService _authService = authService;
    private readonly IRabbitMQClient _rabbitMQClient = rabbitMQClient;

    /// <summary>
    /// Inicia sesión de un usuario.
    /// </summary>
    /// <param name="userLogin">Datos de inicio de sesión del usuario.</param>
    /// <returns>Resultado de la autenticación.</returns>
    [HttpPost("login")]
    public async Task<IActionResult> Login(UserLogin userLogin)
    {
      try
      {
        LoginResult tokens = await _authService.Authenticate(userLogin);
        if (tokens == null) return Unauthorized();
        _rabbitMQClient.Publish("User logged in: " + userLogin.Email);
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

    /// <summary>
    /// Registra un nuevo usuario.
    /// </summary>
    /// <param name="userRegister">Datos de registro del usuario.</param>
    /// <returns>Resultado del registro.</returns>
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

    /// <summary>
    /// Refresca el token de autenticación.
    /// </summary>
    /// <param name="refreshToken">Token de refresco.</param>
    /// <returns>Nuevo token de autenticación.</returns>
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

    /// <summary>
    /// Solicita un token de restablecimiento de contraseña.
    /// </summary>
    /// <param name="request">Solicitud de restablecimiento de contraseña.</param>
    /// <returns>Resultado de la solicitud.</returns>
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

    /// <summary>
    /// Restablece la contraseña del usuario.
    /// </summary>
    /// <param name="request">Solicitud de restablecimiento de contraseña.</param>
    /// <returns>Resultado del restablecimiento.</returns>
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
