using System.Text.Json;
using ms_auth.Models;
using ms_auth.Services;
/*
public class MessageProcessor : IMessageProcessor
{
  
  private readonly IAuthService _authService;

  /// <summary>
  /// Inicializa una nueva instancia de la clase <see cref="MessageProcessor"/>.
  /// </summary>
  /// <param name="authService">El servicio de autenticación.</param>
  public MessageProcessor(IAuthService authService)
  {
    _authService = authService;
  }

  /// <summary>
  /// Procesa el mensaje entrante.
  /// </summary>
  /// <param name="message">El mensaje a procesar.</param>
  public async Task ProcessMessage(string message)
  {
    UserMessage userMessage;
    try
    {
      var options = new JsonSerializerOptions
      {
        PropertyNameCaseInsensitive = true
      };
      userMessage = JsonSerializer.Deserialize<UserMessage>(message, options) ?? throw new InvalidOperationException("Deserialized message is null");
    }
    catch (Exception ex)
    {
      Console.WriteLine($"Error deserializing message: {ex.Message}");
      return;
    }

    if (userMessage.Pattern.Cmd == "register_user")
    {
      await RegisterUser(userMessage);
    }
    else if (userMessage.Pattern.Cmd == "login_user")
    {
      await LoginUser(userMessage);
    }
  }

  /// <summary>
  /// Registra un nuevo usuario.
  /// </summary>
  /// <param name="userMessage">El mensaje del usuario que contiene los detalles de registro.</param>
  private async Task<object> RegisterUser(UserMessage userMessage)
  {
    Console.WriteLine("Registering user...");
    var userRegister = new UserRegister
    {
      Email = userMessage.Data.Email,
      Password = userMessage.Data.Password,
      Name = userMessage.Data.Name,
      LastName = userMessage.Data.LastName
    };

    try
    {
      await _authService.Register(userRegister);
      Console.WriteLine($"User {userRegister.Email} registered successfully.");

      // Enviar confirmación a RabbitMQ
      return new
      {
        Status = "Success",
        userRegister.Email,
        Message = "User registered successfully."

      };
    }
    catch (Exception ex)
    {
      Console.WriteLine($"Error registering user: {ex.Message}");
      return new
      {
        Status = "Error",
        userRegister.Email,
        ex.Message
      };
    }
  }

  /// <summary>
  /// Inicia sesión un usuario existente.
  /// </summary>
  /// <param name="userMessage">El mensaje del usuario que contiene los detalles de inicio de sesión.</param>
  private async Task<object> LoginUser(UserMessage userMessage)
  {
    Console.WriteLine("Logging in user...");
    var userLogin = new UserLogin
    {
      Email = userMessage.Data.Email,
      Password = userMessage.Data.Password
    };

    try
    {
      var result = await _authService.Authenticate(userLogin);
      Console.WriteLine($"User {userLogin.Email} logged in successfully.");

      // Enviar confirmación a RabbitMQ
      return new
      {
        Status = "Success",
        userLogin.Email,
        result.Token,
        Message = "User logged in successfully."

      };
    }
    catch (Exception ex)
    {
      Console.WriteLine($"Error logging in user: {ex.Message}");
      return new
      {
        Status = "Error",
        userLogin.Email,
        ex.Message
      };
    }
  }
  
}
*/