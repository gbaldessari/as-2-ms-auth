using Moq;
using Xunit;
using ms_auth.Controllers;
using ms_auth.Services;
using Microsoft.AspNetCore.Mvc;
using ms_auth.Models;
using ms_auth.RabbitMQ;

namespace ms_auth.Tests
{
    /// <summary>
    /// Pruebas unitarias para el controlador de autenticación.
    /// </summary>
    public class AuthControllerTest
    {
        private readonly Mock<IAuthService> _authServiceMock;
        private readonly Mock<IRabbitMQClient> _rabbitMQClientMock;
        private readonly AuthController _controller;

        /// <summary>
        /// Constructor que inicializa los mocks y el controlador.
        /// </summary>
        public AuthControllerTest()
        {
            _authServiceMock = new Mock<IAuthService>();
            _rabbitMQClientMock = new Mock<IRabbitMQClient>();
            _controller = new AuthController(_authServiceMock.Object, _rabbitMQClientMock.Object);
        }

        /// <summary>
        /// Prueba que ForgotPassword devuelva Ok cuando se proporciona un correo electrónico válido.
        /// </summary>
        [Fact]
        public async Task ForgotPassword_ValidEmail_ReturnsOk()
        {
            var request = new ForgotPasswordRequest { Email = "test@example.com" };
            _authServiceMock.Setup(s => s.ForgotPassword(request.Email)).Returns(Task.CompletedTask);

            var result = await _controller.ForgotPassword(request);

            Assert.IsType<OkObjectResult>(result);
        }

        /// <summary>
        /// Prueba que ForgotPassword devuelva BadRequest cuando se proporciona un correo electrónico inválido.
        /// </summary>
        [Fact]
        public async Task ForgotPassword_InvalidEmail_ReturnsBadRequest()
        {
            var request = new ForgotPasswordRequest { Email = "" };

            var result = await _controller.ForgotPassword(request);

            Assert.IsType<BadRequestObjectResult>(result);
        }

        /// <summary>
        /// Prueba que ForgotPassword devuelva BadRequest cuando falta el correo electrónico.
        /// </summary>
        [Fact]
        public async Task ForgotPassword_MissingEmail_ReturnsBadRequest()
        {
            var request = new ForgotPasswordRequest { Email = string.Empty };

            var result = await _controller.ForgotPassword(request);

            Assert.IsType<BadRequestObjectResult>(result);
        }

        /// <summary>
        /// Prueba que ForgotPassword devuelva BadRequest cuando el correo electrónico no existe.
        /// </summary>
        [Fact]
        public async Task ForgotPassword_NonExistentEmail_ReturnsBadRequest()
        {
            var request = new ForgotPasswordRequest { Email = "nonexistent@example.com" };
            _authServiceMock.Setup(s => s.ForgotPassword(request.Email)).ThrowsAsync(new InvalidOperationException("User does not exist."));

            var result = await _controller.ForgotPassword(request);

            Assert.IsType<BadRequestObjectResult>(result);
        }

        /// <summary>
        /// Prueba que Login devuelva Ok cuando se proporcionan credenciales válidas.
        /// </summary>
        [Fact]
        public async Task Login_ValidCredentials_ReturnsOk()
        {
            var userLogin = new UserLogin { Email = "test@example.com", Password = "password" };
            var loginResult = new LoginResult { Token = "token", RefreshToken = "refreshToken" };
            _authServiceMock.Setup(s => s.Authenticate(userLogin)).ReturnsAsync(loginResult);

            var result = await _controller.Login(userLogin);

            Assert.IsType<OkObjectResult>(result);
        }

        /// <summary>
        /// Prueba que Login devuelva Unauthorized cuando se proporcionan credenciales inválidas.
        /// </summary>
        [Fact]
        public async Task Login_InvalidCredentials_ReturnsUnauthorized()
        {
            var userLogin = new UserLogin { Email = "test@example.com", Password = "wrongpassword" };
            _authServiceMock.Setup(s => s.Authenticate(userLogin)).ThrowsAsync(new UnauthorizedAccessException());

            var result = await _controller.Login(userLogin);

            Assert.IsType<UnauthorizedResult>(result);
        }

        /// <summary>
        /// Prueba que Register devuelva Ok cuando se proporciona un usuario válido.
        /// </summary>
        [Fact]
        public async Task Register_ValidUser_ReturnsOk()
        {
            var userRegister = new UserRegister { Email = "test@example.com", Password = "password", Name = "Test", LastName = "User" };
            _authServiceMock.Setup(s => s.Register(userRegister)).Returns(Task.CompletedTask);

            var result = await _controller.Register(userRegister);

            Assert.IsType<OkObjectResult>(result);
        }

        /// <summary>
        /// Prueba que Register devuelva BadRequest cuando el usuario ya existe.
        /// </summary>
        [Fact]
        public async Task Register_ExistingUser_ReturnsBadRequest()
        {
            var userRegister = new UserRegister { Email = "test@example.com", Password = "password", Name = "Test", LastName = "User" };
            _authServiceMock.Setup(s => s.Register(userRegister)).ThrowsAsync(new InvalidOperationException("User already exists."));

            var result = await _controller.Register(userRegister);

            Assert.IsType<BadRequestObjectResult>(result);
        }

        /// <summary>
        /// Prueba que Register devuelva BadRequest cuando se proporciona un usuario inválido.
        /// </summary>
        [Fact]
        public async Task Register_InvalidUser_ReturnsBadRequest()
        {
            var userRegister = new UserRegister { Email = "invalidemail", Password = "password", Name = "Test", LastName = "User" };
            _authServiceMock.Setup(s => s.Register(userRegister)).ThrowsAsync(new InvalidOperationException("Invalid user data."));

            var result = await _controller.Register(userRegister);

            Assert.IsType<BadRequestObjectResult>(result);
        }

        /// <summary>
        /// Prueba que RefreshToken devuelva Ok cuando se proporciona un token válido.
        /// </summary>
        [Fact]
        public void RefreshToken_ValidToken_ReturnsOk()
        {
            var refreshToken = "validRefreshToken";
            var response = new Response { Token = "newToken", RefreshToken = "newRefreshToken" };
            _authServiceMock.Setup(s => s.RefreshToken(refreshToken)).Returns(response);

            var result = _controller.RefreshToken(refreshToken);

            Assert.IsType<OkObjectResult>(result);
        }

        /// <summary>
        /// Prueba que RefreshToken devuelva BadRequest cuando se proporciona un token inválido.
        /// </summary>
        [Fact]
        public void RefreshToken_InvalidToken_ReturnsBadRequest()
        {
            var refreshToken = "invalidRefreshToken";
            _authServiceMock.Setup(s => s.RefreshToken(refreshToken)).Throws(new Exception("Invalid refresh token."));

            var result = _controller.RefreshToken(refreshToken);

            Assert.IsType<BadRequestObjectResult>(result);
        }

        /// <summary>
        /// Prueba que ResetPassword devuelva Ok cuando se proporciona un token válido.
        /// </summary>
        [Fact]
        public async Task ResetPassword_ValidToken_ReturnsOk()
        {
            var request = new ResetPasswordRequest { ResetToken = "validToken", NewPassword = "newPassword" };
            _authServiceMock.Setup(s => s.ResetPassword(request.ResetToken, request.NewPassword)).Returns(Task.CompletedTask);

            var result = await _controller.ResetPassword(request);

            Assert.IsType<OkObjectResult>(result);
        }

        /// <summary>
        /// Prueba que ResetPassword devuelva BadRequest cuando se proporciona un token inválido.
        /// </summary>
        [Fact]
        public async Task ResetPassword_InvalidToken_ReturnsBadRequest()
        {
            var request = new ResetPasswordRequest { ResetToken = "invalidToken", NewPassword = "newPassword" };
            _authServiceMock.Setup(s => s.ResetPassword(request.ResetToken, request.NewPassword)).ThrowsAsync(new InvalidOperationException("Invalid or expired password reset token."));

            var result = await _controller.ResetPassword(request);

            Assert.IsType<BadRequestObjectResult>(result);
        }

        /// <summary>
        /// Prueba que ResetPassword devuelva BadRequest cuando se proporciona un token expirado.
        /// </summary>
        [Fact]
        public async Task ResetPassword_ExpiredToken_ReturnsBadRequest()
        {
            var request = new ResetPasswordRequest { ResetToken = "expiredToken", NewPassword = "newPassword" };
            _authServiceMock.Setup(s => s.ResetPassword(request.ResetToken, request.NewPassword)).ThrowsAsync(new InvalidOperationException("Invalid or expired password reset token."));

            var result = await _controller.ResetPassword(request);

            Assert.IsType<BadRequestObjectResult>(result);
        }
    }
}