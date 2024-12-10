using System;
using System.Text;
using System.Text.Json;
using ms_auth.Models;
using ms_auth.Services;
using RabbitMQ.Client;

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
      SendResponseToRabbitMQ(new { Status = "Error", Message = ex.Message });
      return;
    }

    Console.WriteLine($"Processing message for user: {userMessage.Data.Email}");

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
  private async Task RegisterUser(UserMessage userMessage)
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
      SendResponseToRabbitMQ(new
      {
        Status = "Success",
        Email = userRegister.Email,
        Message = "User registered successfully."
      });
    }
    catch (Exception ex)
    {
      Console.WriteLine($"Error registering user: {ex.Message}");
      SendResponseToRabbitMQ(new { Status = "Error", Message = ex.Message });
    }
  }

  /// <summary>
  /// Inicia sesión un usuario existente.
  /// </summary>
  /// <param name="userMessage">El mensaje del usuario que contiene los detalles de inicio de sesión.</param>
  private async Task LoginUser(UserMessage userMessage)
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
      SendResponseToRabbitMQ(new
      {
        Status = "Success",
        Email = userLogin.Email,
        Token = result.Token,
        Message = "User logged in successfully."
      });
    }
    catch (Exception ex)
    {
      Console.WriteLine($"Error logging in user: {ex.Message}");
      SendResponseToRabbitMQ(new { Status = "Error", Message = ex.Message });
    }
  }

  /// <summary>
  /// Envía un mensaje de respuesta a RabbitMQ.
  /// </summary>
  /// <param name="responseMessage">El mensaje de respuesta a enviar.</param>
  private void SendResponseToRabbitMQ(object responseMessage)
  {
    var factory = new ConnectionFactory()
    {
      HostName = Environment.GetEnvironmentVariable("RABBITMQ_HOST"),
      Port = int.TryParse(Environment.GetEnvironmentVariable("RABBITMQ_PORT"), out int port) ? port : throw new ArgumentNullException("RABBITMQ_PORT"),
      UserName = Environment.GetEnvironmentVariable("RABBITMQ_USERNAME"),
      Password = Environment.GetEnvironmentVariable("RABBITMQ_PASSWORD"),
      VirtualHost = Environment.GetEnvironmentVariable("RABBITMQ_VHOST")
    };

    using var connection = factory.CreateConnection();
    using var channel = connection.CreateModel();
    channel.QueueDeclare(queue: Environment.GetEnvironmentVariable("RABBITMQ_RESPONSES_QUEUE"),
                         durable: false,
                         exclusive: false,
                         autoDelete: false,
                         arguments: null);

    var body = Encoding.UTF8.GetBytes(JsonSerializer.Serialize(responseMessage));

    channel.BasicPublish(exchange: "",
                         routingKey: Environment.GetEnvironmentVariable("RABBITMQ_RESPONSES_QUEUE"),
                         basicProperties: null,
                         body: body);

    Console.WriteLine("Sent response message to RabbitMQ: " + responseMessage);
  }
}
