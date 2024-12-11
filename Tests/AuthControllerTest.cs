// using Moq;
// using Xunit;
// using ms_auth.Controllers;
// using ms_auth.Services;
// using Microsoft.AspNetCore.Mvc;
// using ms_auth.Models;
// using ms_auth.RabbitMQ;

// namespace ms_auth.Tests
// {
//     public class AuthControllerTest
//     {
//         private readonly Mock<IAuthService> _authServiceMock;
//         private readonly AuthController _controller;

//         public AuthControllerTest()
//         {
//             _authServiceMock = new Mock<IAuthService>();
//             _controller = new AuthController(_authServiceMock.Object);
//         }

//         [Fact]
//         public async Task ForgotPassword_ValidEmail_ReturnsOk()
//         {
//             var request = new ForgotPasswordRequest { Email = "test@example.com" };
//             _authServiceMock.Setup(s => s.ForgotPassword(request.Email)).Returns(Task.CompletedTask);

//             var result = await _controller.ForgotPassword(request);

//             Assert.IsType<OkObjectResult>(result);
//         }

//         [Fact]
//         public async Task ForgotPassword_InvalidEmail_ReturnsBadRequest()
//         {
//             var request = new ForgotPasswordRequest { Email = "" };

//             var result = await _controller.ForgotPassword(request);

//             Assert.IsType<BadRequestObjectResult>(result);
//         }

//         [Fact]
//         public async Task ForgotPassword_MissingEmail_ReturnsBadRequest()
//         {
//             var request = new ForgotPasswordRequest { Email = string.Empty };

//             var result = await _controller.ForgotPassword(request);

//             Assert.IsType<BadRequestObjectResult>(result);
//         }

//         [Fact]
//         public async Task ForgotPassword_NonExistentEmail_ReturnsBadRequest()
//         {
//             var request = new ForgotPasswordRequest { Email = "nonexistent@example.com" };
//             _authServiceMock.Setup(s => s.ForgotPassword(request.Email)).ThrowsAsync(new InvalidOperationException("User does not exist."));

//             var result = await _controller.ForgotPassword(request);

//             Assert.IsType<BadRequestObjectResult>(result);
//         }

//         [Fact]
//         public async Task Login_ValidCredentials_ReturnsOk()
//         {
//             var userLogin = new UserLogin { Email = "test@example.com", Password = "password" };
//             var loginResult = new LoginResponse { Token = "token", RefreshToken = "refreshToken" };
//             _authServiceMock.Setup(s => s.Authenticate(userLogin)).ReturnsAsync(loginResult);

//             var result = await _controller.Login(userLogin);

//             Assert.IsType<OkObjectResult>(result);
//         }

//         [Fact]
//         public async Task Login_InvalidCredentials_ReturnsUnauthorized()
//         {
//             var userLogin = new UserLogin { Email = "test@example.com", Password = "wrongpassword" };
//             _authServiceMock.Setup(s => s.Authenticate(userLogin)).ThrowsAsync(new UnauthorizedAccessException());

//             var result = await _controller.Login(userLogin);

//             Assert.IsType<UnauthorizedResult>(result);
//         }

//         [Fact]
//         public async Task Register_ValidUser_ReturnsOk()
//         {
//             var userRegister = new UserRegister { Email = "test@example.com", Password = "password", Name = "Test", LastName = "User" };
//             _authServiceMock.Setup(s => s.Register(userRegister)).Returns(Task.CompletedTask);

//             var result = await _controller.Register(userRegister);

//             Assert.IsType<OkObjectResult>(result);
//         }

//         [Fact]
//         public async Task Register_ExistingUser_ReturnsBadRequest()
//         {
//             var userRegister = new UserRegister { Email = "test@example.com", Password = "password", Name = "Test", LastName = "User" };
//             _authServiceMock.Setup(s => s.Register(userRegister)).ThrowsAsync(new InvalidOperationException("User already exists."));

//             var result = await _controller.Register(userRegister);

//             Assert.IsType<BadRequestObjectResult>(result);
//         }

//         [Fact]
//         public async Task Register_InvalidUser_ReturnsBadRequest()
//         {
//             var userRegister = new UserRegister { Email = "invalidemail", Password = "password", Name = "Test", LastName = "User" };
//             _authServiceMock.Setup(s => s.Register(userRegister)).ThrowsAsync(new InvalidOperationException("Invalid user data."));

//             var result = await _controller.Register(userRegister);

//             Assert.IsType<BadRequestObjectResult>(result);
//         }

//         [Fact]
//         public async Task RefreshToken_ValidToken_ReturnsOk()
//         {
//             var refreshToken = "validRefreshToken";
//             var response = new LoginResponse { Token = "newToken", RefreshToken = "newRefreshToken" };
//             _authServiceMock.Setup(s => s.RefreshToken(refreshToken)).ReturnsAsync(response);

//             var result = await _controller.RefreshToken(refreshToken);

//             Assert.IsType<OkObjectResult>(result);
//         }

//         [Fact]
//         public async Task RefreshToken_InvalidToken_ReturnsBadRequest()
//         {
//             var refreshToken = "invalidRefreshToken";
//             _authServiceMock.Setup(s => s.RefreshToken(refreshToken)).ThrowsAsync(new Exception("Invalid refresh token."));

//             var result = await _controller.RefreshToken(refreshToken);

//             Assert.IsType<BadRequestObjectResult>(result);
//         }

//         [Fact]
//         public async Task ResetPassword_ValidToken_ReturnsOk()
//         {
//             var request = new ResetPasswordRequest { ResetToken = "validToken", NewPassword = "newPassword" };
//             _authServiceMock.Setup(s => s.ResetPassword(request.ResetToken, request.NewPassword)).Returns(Task.CompletedTask);

//             var result = await _controller.ResetPassword(request);

//             Assert.IsType<OkObjectResult>(result);
//         }

//         [Fact]
//         public async Task ResetPassword_InvalidToken_ReturnsBadRequest()
//         {
//             var request = new ResetPasswordRequest { ResetToken = "invalidToken", NewPassword = "newPassword" };
//             _authServiceMock.Setup(s => s.ResetPassword(request.ResetToken, request.NewPassword)).ThrowsAsync(new InvalidOperationException("Invalid or expired password reset token."));

//             var result = await _controller.ResetPassword(request);

//             Assert.IsType<BadRequestObjectResult>(result);
//         }

//         [Fact]
//         public async Task ResetPassword_ExpiredToken_ReturnsBadRequest()
//         {
//             var request = new ResetPasswordRequest { ResetToken = "expiredToken", NewPassword = "newPassword" };
//             _authServiceMock.Setup(s => s.ResetPassword(request.ResetToken, request.NewPassword)).ThrowsAsync(new InvalidOperationException("Invalid or expired password reset token."));

//             var result = await _controller.ResetPassword(request);

//             Assert.IsType<BadRequestObjectResult>(result);
//         }
//     }
// }