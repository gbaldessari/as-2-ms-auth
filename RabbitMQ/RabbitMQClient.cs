using RabbitMQ.Client;
using RabbitMQ.Client.Events;
using System.Text;

namespace ms_auth.Services
{
    public class RabbitMQClient : IDisposable
    {
        private readonly IConnection _connection;
        private readonly IModel _channel;
        private readonly string _queueName;
        private readonly IServiceScopeFactory _serviceScopeFactory;

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

        public void Publish(string message)
        {
            var body = Encoding.UTF8.GetBytes(message);
            _channel.BasicPublish(exchange: "",
                                 routingKey: _queueName,
                                 basicProperties: null,
                                 body: body);
        }

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

        public void Dispose()
        {
            _channel?.Close();
            _connection?.Close();
        }
    }
}