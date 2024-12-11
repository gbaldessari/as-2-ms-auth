using ms_auth.Models;
using RabbitMQ.Client;
using RabbitMQ.Client.Events;
using System.Text;

namespace ms_auth.RabbitMQ
{
  /*
  /// <summary>
  /// Interface para el cliente de RabbitMQ.
  /// </summary>
  public interface IRabbitMQClient
  {
    /// <summary>
    /// Publica un mensaje en la cola de RabbitMQ.
    /// </summary>
    /// <param name="message">El mensaje a publicar.</param>
    void Publish(string message);

    /// <summary>
    /// Consume mensajes de la cola de RabbitMQ.
    /// </summary>
    void Consume();

    /// <summary>
    /// Libera los recursos utilizados por el cliente de RabbitMQ.
    /// </summary>
    void Dispose();
  }

  /// <summary>
  /// Implementación del cliente de RabbitMQ.
  /// </summary>
  public class RabbitMQClient : IRabbitMQClient
  {
    private readonly IConnection _connection;
    private readonly IModel _channel;
    private readonly string _queueName;
    private readonly IServiceScopeFactory _serviceScopeFactory;

    /// <summary>
    /// Inicializa una nueva instancia de la clase <see cref="RabbitMQClient"/>.
    /// </summary>
    /// <param name="serviceScopeFactory">La fábrica de ámbitos de servicio.</param>
    public RabbitMQClient(IServiceScopeFactory serviceScopeFactory)
    {
      var factory = new ConnectionFactory()
      {
        HostName = Environment.GetEnvironmentVariable("RABBITMQ_HOST"),
        Port = int.TryParse(Environment.GetEnvironmentVariable("RABBITMQ_PORT"), out int port) ? port : throw new ArgumentNullException("RABBITMQ_PORT"),
        UserName = Environment.GetEnvironmentVariable("RABBITMQ_USERNAME"),
        Password = Environment.GetEnvironmentVariable("RABBITMQ_PASSWORD"),
        VirtualHost = Environment.GetEnvironmentVariable("RABBITMQ_VHOST")
      };

      _connection = factory.CreateConnection();
      _channel = _connection.CreateModel();
      _queueName = Environment.GetEnvironmentVariable("RABBITMQ_QUEUE") ?? throw new ArgumentNullException("RABBITMQ_QUEUE");
      _serviceScopeFactory = serviceScopeFactory;

      _channel.QueueDeclare(queue: _queueName,
                           durable: true,
                           exclusive: false,
                           autoDelete: false,
                           arguments: null);
      
    }

    /// <summary>
    /// Publica un mensaje en la cola de RabbitMQ.
    /// </summary>
    /// <param name="message">El mensaje a publicar.</param>
    public void Publish(string message)
    {
      var body = Encoding.UTF8.GetBytes(message);
      _channel.BasicPublish(exchange: "",
                           routingKey: _queueName,
                           basicProperties: null,
                           body: body);
    }

    /// <summary>
    /// Consume mensajes de la cola de RabbitMQ.
    /// </summary>
    public void Consume()
    {
      var consumer = new EventingBasicConsumer(_channel);
      consumer.Received += (model, ea) =>
      {
        var body = ea.Body.ToArray();
        var message = Encoding.UTF8.GetString(body);
        Console.WriteLine($"Message received: {message}");

        using (var scope = _serviceScopeFactory.CreateScope())
        {
          var messageProcessor = scope.ServiceProvider.GetRequiredService<IMessageProcessor>();
          messageProcessor.ProcessMessage(message);
        }
      };

      _channel.BasicConsume(queue: _queueName,
                           autoAck: true,
                           consumer: consumer);
    }

    /// <summary>
    /// Libera los recursos utilizados por el cliente de RabbitMQ.
    /// </summary>
    public void Dispose()
    {
      _channel?.Close();
      _connection?.Close();
    }
  }
  */
}
