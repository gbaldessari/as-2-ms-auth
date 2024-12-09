using Moq;
using Xunit;
using ms_auth.Controllers;
using ms_auth.Services;
using Microsoft.AspNetCore.Mvc;
using ms_auth.Models;

public class AuthControllerTest
{
    private readonly Mock<IAuthService> _authServiceMock;
    private readonly Mock<IRabbitMQClient> _rabbitMQClientMock;
    private readonly AuthController _controller;

    public AuthControllerTest()
    {
        _authServiceMock = new Mock<IAuthService>();
        _rabbitMQClientMock = new Mock<IRabbitMQClient>();
        _controller = new AuthController(_authServiceMock.Object, _rabbitMQClientMock.Object);
    }

    [Fact]
    public async Task ForgotPassword_ValidEmail_ReturnsOk()
    {
        // Arrange
        var request = new ForgotPasswordRequest { Email = "test@example.com" };
        _authServiceMock.Setup(s => s.ForgotPassword(request.Email)).Returns(Task.CompletedTask);

        // Act
        var result = await _controller.ForgotPassword(request);

        // Assert
        Assert.IsType<OkObjectResult>(result);
    }

    [Fact]
    public async Task ForgotPassword_InvalidEmail_ReturnsBadRequest()
    {
        // Arrange
        var request = new ForgotPasswordRequest { Email = "" };

        // Act
        var result = await _controller.ForgotPassword(request);

        // Assert
        Assert.IsType<BadRequestObjectResult>(result);
    }

    [Fact]
    public async Task ForgotPassword_MissingEmail_ReturnsBadRequest()
    {
        // Arrange
        var request = new ForgotPasswordRequest { Email = string.Empty };

        // Act
        var result = await _controller.ForgotPassword(request);

        // Assert
        Assert.IsType<BadRequestObjectResult>(result);
    }

    [Fact]
    public async Task ForgotPassword_NonExistentEmail_ReturnsBadRequest()
    {
        // Arrange
        var request = new ForgotPasswordRequest { Email = "nonexistent@example.com" };
        _authServiceMock.Setup(s => s.ForgotPassword(request.Email)).ThrowsAsync(new InvalidOperationException("User does not exist."));

        // Act
        var result = await _controller.ForgotPassword(request);

        // Assert
        Assert.IsType<BadRequestObjectResult>(result);
    }

    [Fact]
    public async Task Login_ValidCredentials_ReturnsOk()
    {
        // Arrange
        var userLogin = new UserLogin { Email = "test@example.com", Password = "password" };
        var loginResult = new LoginResult { Token = "token", RefreshToken = "refreshToken" };
        _authServiceMock.Setup(s => s.Authenticate(userLogin)).ReturnsAsync(loginResult);

        // Act
        var result = await _controller.Login(userLogin);

        // Assert
        Assert.IsType<OkObjectResult>(result);
    }

    [Fact]
    public async Task Login_InvalidCredentials_ReturnsUnauthorized()
    {
        // Arrange
        var userLogin = new UserLogin { Email = "test@example.com", Password = "wrongpassword" };
        _authServiceMock.Setup(s => s.Authenticate(userLogin)).ThrowsAsync(new UnauthorizedAccessException());

        // Act
        var result = await _controller.Login(userLogin);

        // Assert
        Assert.IsType<UnauthorizedResult>(result);
    }

    [Fact]
    public async Task Register_ValidUser_ReturnsOk()
    {
        // Arrange
        var userRegister = new UserRegister { Email = "test@example.com", Password = "password", Name = "Test", LastName = "User" };
        _authServiceMock.Setup(s => s.Register(userRegister)).Returns(Task.CompletedTask);

        // Act
        var result = await _controller.Register(userRegister);

        // Assert
        Assert.IsType<OkObjectResult>(result);
    }

    [Fact]
    public async Task Register_ExistingUser_ReturnsBadRequest()
    {
        // Arrange
        var userRegister = new UserRegister { Email = "test@example.com", Password = "password", Name = "Test", LastName = "User" };
        _authServiceMock.Setup(s => s.Register(userRegister)).ThrowsAsync(new InvalidOperationException("User already exists."));

        // Act
        var result = await _controller.Register(userRegister);

        // Assert
        Assert.IsType<BadRequestObjectResult>(result);
    }

    [Fact]
    public async Task Register_InvalidUser_ReturnsBadRequest()
    {
        // Arrange
        var userRegister = new UserRegister { Email = "invalidemail", Password = "password", Name = "Test", LastName = "User" };
        _authServiceMock.Setup(s => s.Register(userRegister)).ThrowsAsync(new InvalidOperationException("Invalid user data."));

        // Act
        var result = await _controller.Register(userRegister);

        // Assert
        Assert.IsType<BadRequestObjectResult>(result);
    }

    [Fact]
    public void RefreshToken_ValidToken_ReturnsOk()
    {
        // Arrange
        var refreshToken = "validRefreshToken";
        var response = new Response { Token = "newToken", RefreshToken = "newRefreshToken" };
        _authServiceMock.Setup(s => s.RefreshToken(refreshToken)).Returns(response);

        // Act
        var result = _controller.RefreshToken(refreshToken);

        // Assert
        Assert.IsType<OkObjectResult>(result);
    }

    [Fact]
    public void RefreshToken_InvalidToken_ReturnsBadRequest()
    {
        // Arrange
        var refreshToken = "invalidRefreshToken";
        _authServiceMock.Setup(s => s.RefreshToken(refreshToken)).Throws(new Exception("Invalid refresh token."));

        // Act
        var result = _controller.RefreshToken(refreshToken);

        // Assert
        Assert.IsType<BadRequestObjectResult>(result);
    }

    [Fact]
    public async Task ResetPassword_ValidToken_ReturnsOk()
    {
        // Arrange
        var request = new ResetPasswordRequest { ResetToken = "validToken", NewPassword = "newPassword" };
        _authServiceMock.Setup(s => s.ResetPassword(request.ResetToken, request.NewPassword)).Returns(Task.CompletedTask);

        // Act
        var result = await _controller.ResetPassword(request);

        // Assert
        Assert.IsType<OkObjectResult>(result);
    }

    [Fact]
    public async Task ResetPassword_InvalidToken_ReturnsBadRequest()
    {
        // Arrange
        var request = new ResetPasswordRequest { ResetToken = "invalidToken", NewPassword = "newPassword" };
        _authServiceMock.Setup(s => s.ResetPassword(request.ResetToken, request.NewPassword)).ThrowsAsync(new InvalidOperationException("Invalid or expired password reset token."));

        // Act
        var result = await _controller.ResetPassword(request);

        // Assert
        Assert.IsType<BadRequestObjectResult>(result);
    }

    [Fact]
    public async Task ResetPassword_ExpiredToken_ReturnsBadRequest()
    {
        // Arrange
        var request = new ResetPasswordRequest { ResetToken = "expiredToken", NewPassword = "newPassword" };
        _authServiceMock.Setup(s => s.ResetPassword(request.ResetToken, request.NewPassword)).ThrowsAsync(new InvalidOperationException("Invalid or expired password reset token."));

        // Act
        var result = await _controller.ResetPassword(request);

        // Assert
        Assert.IsType<BadRequestObjectResult>(result);
    }
}