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
    public async Task<ServiceResponse<LoginResponse>> Login(UserLogin userLogin)
    {
      ServiceResponse<LoginResponse> response = await _authService.Authenticate(userLogin);
      return response;
    }

    [HttpPost("register")]
    public async Task<ServiceResponse<string>> Register([FromBody] UserRegister userRegister)
    {
      ServiceResponse<string> response = await _authService.Register(userRegister);
      return response;
    }

    [HttpPost("refresh-token")]
    public async Task<ServiceResponse<LoginResponse>> RefreshToken(string refreshToken)
    {
      ServiceResponse<LoginResponse> response = await _authService.RefreshToken(refreshToken);
      return response;
    }

    [HttpPost("forgot-password")]
    public async Task<ServiceResponse<string>> ForgotPassword([FromBody] ForgotPasswordRequest request)
    {
      ServiceResponse<string> response = await _authService.ForgotPassword(request.Email);
      return response;
    }

    [HttpPost("reset-password")]
    public async Task<ServiceResponse<string>> ResetPassword([FromBody] ResetPasswordRequest request)
    {
      ServiceResponse<string> response = await _authService.ResetPassword(request.ResetToken, request.NewPassword);
      return response;
    }
  }
}
