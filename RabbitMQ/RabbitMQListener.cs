using ms_auth.Services;
using RabbitMQ.Client;
using Newtonsoft.Json;
using System.Text;
using RabbitMQ.Client.Events;
using ms_auth.Models;

public class RabbitMQListener(IAuthService authService)
{
  private readonly IAuthService _authService = authService;

  public void Start()
  {
    var factory = new ConnectionFactory() { HostName = "localhost" };
    using var connection = factory.CreateConnection();
    using var channel = connection.CreateModel();

    channel.QueueDeclare(queue: "auth_service_queue",
      durable: true,
      exclusive: false,
      autoDelete: false,
      arguments: null
    );

    var consumer = new EventingBasicConsumer(channel);
    consumer.Received += async (model, ea) =>
    {
      var body = ea.Body.ToArray();
      var message = Encoding.UTF8.GetString(body);

      // Deserializar el mensaje
      var payload = JsonConvert.DeserializeObject<Dictionary<string, string>>(message);

      if (payload != null && payload.ContainsKey("username") && payload.ContainsKey("password"))
      {
        await _authService.Register(new UserRegister
        {
          Password = payload["password"],
          Name = payload.ContainsKey("name") ? payload["name"] : string.Empty,
          LastName = payload.ContainsKey("lastName") ? payload["lastName"] : string.Empty,
          Email = payload.ContainsKey("email") ? payload["email"] : string.Empty
        });
      }

      // Acknowledge the message
      channel.BasicAck(deliveryTag: ea.DeliveryTag, multiple: false);
    };

    channel.BasicConsume(queue: "auth_service_queue",
      autoAck: false,
      consumer: consumer
    );

    Console.WriteLine("Listening for messages on RabbitMQ...");
    Console.ReadLine();
  }
}
