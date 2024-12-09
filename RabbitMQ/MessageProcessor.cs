using System;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using ms_auth.Services;
using RabbitMQ.Client;

public class MessageProcessor : IMessageProcessor
{
    private readonly IAuthService _authService;

    public MessageProcessor(IAuthService authService)
    {
        _authService = authService;
    }

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

        // Procesar el mensaje
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

public interface IMessageProcessor
{
    Task ProcessMessage(string message);
}

public class UserMessage
{
    public required Pattern Pattern { get; set; }
    public required Data Data { get; set; }
    public required string Id { get; set; }
}

public class Pattern
{
    public required string Cmd { get; set; }
}

public class Data
{
    public required string Email { get; set; }
    public required string Password { get; set; }
    public required string Name { get; set; }
    public required string LastName { get; set; }
}

public class UserRegister
{
    public required string Email { get; set; }
    public required string Password { get; set; }
    public required string Name { get; set; }
    public required string LastName { get; set; }
}

public class UserLogin
{
    public required string Email { get; set; }
    public required string Password { get; set; }
}

public class LoginResult
{
    public required string Token { get; set; }
}