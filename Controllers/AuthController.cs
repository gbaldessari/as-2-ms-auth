using ms_auth.Models;
using ms_auth.Services;
using Microsoft.AspNetCore.Mvc;

namespace ms_auth.Controllers
{
  [ApiController]
  [Route("api/[controller]")]
  public class AuthController : ControllerBase
  {
    private readonly IAuthService _authService;

    public AuthController(IAuthService authService)
    {
      _authService = authService;
    }

    [HttpPost("login")]
    public IActionResult Login([FromBody] UserLogin userLogin)
    {
      var token = _authService.Authenticate(userLogin);

      if (token == null)
        return Unauthorized();

      return Ok(new { token });
    }
  }
}
