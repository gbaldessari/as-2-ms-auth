using Microsoft.AspNetCore.Mvc;
using Moq;
using ms_auth.Controllers;
using ms_auth.Models;
using ms_auth.Services;
using Xunit;

namespace ms_auth.Tests
{
    public class AuthControllerTest
    {
        private readonly Mock<IAuthService> _authServiceMock;
        private readonly AuthController _authController;

        public AuthControllerTest()
        {
            _authServiceMock = new Mock<IAuthService>();
            _authController = new AuthController(_authServiceMock.Object);
        }

        [Fact]
        public async Task Login_ReturnsServiceResponse_WithLoginResponse()
        {
            // Arrange
            var userLogin = new UserLogin { Email = "test@example.com", Password = "password" };
            var serviceResponse = new ServiceResponse<LoginResponse>
            {
                Data = new LoginResponse { Token = "jwtToken", RefreshToken = "refreshToken" },
                Success = true
            };
            _authServiceMock.Setup(s => s.Authenticate(userLogin)).ReturnsAsync(serviceResponse);

            // Act
            var result = await _authController.Login(userLogin);

            // Assert
            Assert.Equal(serviceResponse, result);
        }

        [Fact]
        public async Task Register_ReturnsServiceResponse_WithString()
        {
            // Arrange
            var userRegister = new UserRegister { Name = "John", LastName = "Doe", Email = "john.doe@example.com", Password = "password" };
            var serviceResponse = new ServiceResponse<string> { Data = "User registered successfully.", Success = true };
            _authServiceMock.Setup(s => s.Register(userRegister)).ReturnsAsync(serviceResponse);

            // Act
            var result = await _authController.Register(userRegister);

            // Assert
            Assert.Equal(serviceResponse, result);
        }

        [Fact]
        public async Task RefreshToken_ReturnsServiceResponse_WithLoginResponse()
        {
            // Arrange
            var refreshToken = "refreshToken";
            var serviceResponse = new ServiceResponse<LoginResponse>
            {
                Data = new LoginResponse { Token = "newJwtToken", RefreshToken = "newRefreshToken" },
                Success = true
            };
            _authServiceMock.Setup(s => s.RefreshToken(refreshToken)).ReturnsAsync(serviceResponse);

            // Act
            var result = await _authController.RefreshToken(refreshToken);

            // Assert
            Assert.Equal(serviceResponse, result);
        }

        [Fact]
        public async Task ForgotPassword_ReturnsServiceResponse_WithString()
        {
            // Arrange
            var request = new ForgotPasswordRequest { Email = "test@example.com" };
            var serviceResponse = new ServiceResponse<string> { Data = "Password reset email sent.", Success = true };
            _authServiceMock.Setup(s => s.ForgotPassword(request.Email)).ReturnsAsync(serviceResponse);

            // Act
            var result = await _authController.ForgotPassword(request);

            // Assert
            Assert.Equal(serviceResponse, result);
        }

        [Fact]
        public async Task ResetPassword_ReturnsServiceResponse_WithString()
        {
            // Arrange
            var request = new ResetPasswordRequest { ResetToken = "resetToken", NewPassword = "newPassword" };
            var serviceResponse = new ServiceResponse<string> { Data = "Password reset successfully.", Success = true };
            _authServiceMock.Setup(s => s.ResetPassword(request.ResetToken, request.NewPassword)).ReturnsAsync(serviceResponse);

            // Act
            var result = await _authController.ResetPassword(request);

            // Assert
            Assert.Equal(serviceResponse, result);
        }

        [Fact]
        public async Task Login_ReturnsError_WhenInvalidCredentials()
        {
            // Arrange
            var userLogin = new UserLogin { Email = "invalid@example.com", Password = "wrongpassword" };
            var serviceResponse = new ServiceResponse<LoginResponse>
            {
                Success = false,
                Error = "Invalid username or password."
            };
            _authServiceMock.Setup(s => s.Authenticate(userLogin)).ReturnsAsync(serviceResponse);

            // Act
            var result = await _authController.Login(userLogin);

            // Assert
            Assert.Equal(serviceResponse, result);
        }

        [Fact]
        public async Task Register_ReturnsError_WhenUserAlreadyExists()
        {
            // Arrange
            var userRegister = new UserRegister { Name = "John", LastName = "Doe", Email = "existing@example.com", Password = "password" };
            var serviceResponse = new ServiceResponse<string> { Success = false, Error = "User already exists." };
            _authServiceMock.Setup(s => s.Register(userRegister)).ReturnsAsync(serviceResponse);

            // Act
            var result = await _authController.Register(userRegister);

            // Assert
            Assert.Equal(serviceResponse, result);
        }

        [Fact]
        public async Task RefreshToken_ReturnsError_WhenInvalidToken()
        {
            // Arrange
            var refreshToken = "invalidRefreshToken";
            var serviceResponse = new ServiceResponse<LoginResponse> { Success = false, Error = "Invalid refresh token." };
            _authServiceMock.Setup(s => s.RefreshToken(refreshToken)).ReturnsAsync(serviceResponse);

            // Act
            var result = await _authController.RefreshToken(refreshToken);

            // Assert
            Assert.Equal(serviceResponse, result);
        }

        [Fact]
        public async Task ForgotPassword_ReturnsError_WhenUserDoesNotExist()
        {
            // Arrange
            var request = new ForgotPasswordRequest { Email = "nonexistent@example.com" };
            var serviceResponse = new ServiceResponse<string> { Success = false, Error = "User does not exist." };
            _authServiceMock.Setup(s => s.ForgotPassword(request.Email)).ReturnsAsync(serviceResponse);

            // Act
            var result = await _authController.ForgotPassword(request);

            // Assert
            Assert.Equal(serviceResponse, result);
        }

        [Fact]
        public async Task ResetPassword_ReturnsError_WhenInvalidToken()
        {
            // Arrange
            var request = new ResetPasswordRequest { ResetToken = "invalidResetToken", NewPassword = "newPassword" };
            var serviceResponse = new ServiceResponse<string> { Success = false, Error = "Invalid or expired password reset token." };
            _authServiceMock.Setup(s => s.ResetPassword(request.ResetToken, request.NewPassword)).ReturnsAsync(serviceResponse);

            // Act
            var result = await _authController.ResetPassword(request);

            // Assert
            Assert.Equal(serviceResponse, result);
        }

        [Fact]
        public async Task Login_ReturnsError_WhenUserNotFound()
        {
            // Arrange
            var userLogin = new UserLogin { Email = "nonexistent@example.com", Password = "password" };
            var serviceResponse = new ServiceResponse<LoginResponse>
            {
                Success = false,
                Error = "User not found."
            };
            _authServiceMock.Setup(s => s.Authenticate(userLogin)).ReturnsAsync(serviceResponse);

            // Act
            var result = await _authController.Login(userLogin);

            // Assert
            Assert.Equal(serviceResponse, result);
        }

        [Fact]
        public async Task Register_ReturnsError_WhenEmailInvalid()
        {
            // Arrange
            var userRegister = new UserRegister { Name = "John", LastName = "Doe", Email = "invalid-email", Password = "password" };
            var serviceResponse = new ServiceResponse<string> { Success = false, Error = "Invalid email format." };
            _authServiceMock.Setup(s => s.Register(userRegister)).ReturnsAsync(serviceResponse);

            // Act
            var result = await _authController.Register(userRegister);

            // Assert
            Assert.Equal(serviceResponse, result);
        }

        [Fact]
        public async Task RefreshToken_ReturnsError_WhenTokenExpired()
        {
            // Arrange
            var refreshToken = "expiredRefreshToken";
            var serviceResponse = new ServiceResponse<LoginResponse> { Success = false, Error = "Refresh token expired." };
            _authServiceMock.Setup(s => s.RefreshToken(refreshToken)).ReturnsAsync(serviceResponse);

            // Act
            var result = await _authController.RefreshToken(refreshToken);

            // Assert
            Assert.Equal(serviceResponse, result);
        }

        [Fact]
        public async Task ForgotPassword_ReturnsError_WhenEmailInvalid()
        {
            // Arrange
            var request = new ForgotPasswordRequest { Email = "invalid-email" };
            var serviceResponse = new ServiceResponse<string> { Success = false, Error = "Invalid email format." };
            _authServiceMock.Setup(s => s.ForgotPassword(request.Email)).ReturnsAsync(serviceResponse);

            // Act
            var result = await _authController.ForgotPassword(request);

            // Assert
            Assert.Equal(serviceResponse, result);
        }

        [Fact]
        public async Task ResetPassword_ReturnsError_WhenPasswordWeak()
        {
            // Arrange
            var request = new ResetPasswordRequest { ResetToken = "validResetToken", NewPassword = "123" };
            var serviceResponse = new ServiceResponse<string> { Success = false, Error = "Password is too weak." };
            _authServiceMock.Setup(s => s.ResetPassword(request.ResetToken, request.NewPassword)).ReturnsAsync(serviceResponse);

            // Act
            var result = await _authController.ResetPassword(request);

            // Assert
            Assert.Equal(serviceResponse, result);
        }
    }
}