using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using System.Text;
using DotNetEnv;
using ms_auth.Services;
using MongoDB.Driver;
using ms_auth.RabbitMQ;
using ms_auth.Models;

WebApplicationBuilder builder = WebApplication.CreateBuilder(args);

// Cargar las variables de entorno desde el archivo .env
Env.Load();

// Leer y validar las variables de entorno requeridas
string jwtIssuer = Environment.GetEnvironmentVariable("JWT_ISSUER") ?? throw new ArgumentNullException("JWT_ISSUER", "JWT Issuer cannot be null.");
string jwtAudience = Environment.GetEnvironmentVariable("JWT_AUDIENCE") ?? throw new ArgumentNullException("JWT_AUDIENCE", "JWT Audience cannot be null.");
string jwtKey = Environment.GetEnvironmentVariable("JWT_KEY") ?? throw new ArgumentNullException("JWT_KEY", "JWT Key cannot be null.");
string? mongoConnectionString = Environment.GetEnvironmentVariable("MONGO_CONNECTION_STRING");
string? mongoDatabaseName = Environment.GetEnvironmentVariable("MONGO_DATABASE_NAME");

// Probar la conexión a MongoDB al inicio
IMongoDatabase? database = null;
try
{
    var client = new MongoClient(mongoConnectionString);
    database = client.GetDatabase(mongoDatabaseName);
    Console.WriteLine("Connected to MongoDB.");
}
catch (Exception ex)
{
    Console.WriteLine("Error connecting to MongoDB: " + ex.Message);
}

// Configurar autenticación JWT
builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme).AddJwtBearer(options =>
{
    options.TokenValidationParameters = new TokenValidationParameters
    {
        ValidateIssuer = true,
        ValidateAudience = true,
        ValidateLifetime = true,
        ValidateIssuerSigningKey = true,
        ValidIssuer = jwtIssuer,
        ValidAudience = jwtAudience,
        IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtKey))
    };
});

// Agregar autorización y controladores
builder.Services.AddAuthorization();
builder.Services.AddControllers();
builder.Services.AddScoped<IAuthService, AuthService>();

// Registrar el cliente de MongoDB
builder.Services.AddSingleton<IMongoClient, MongoClient>(sp => new MongoClient(mongoConnectionString));
builder.Services.AddSingleton<RabbitMQClient>();
builder.Services.AddScoped<IMessageProcessor, MessageProcessor>();

// Registrar la base de datos de MongoDB
builder.Services.AddScoped(sp => sp.GetRequiredService<IMongoClient>().GetDatabase(mongoDatabaseName));

var app = builder.Build();

if (app.Environment.IsDevelopment()) {
    app.UseSwagger();
    app.UseSwaggerUI();
}

// Usar autenticación y autorización
app.UseAuthentication();
app.UseAuthorization();

// Mapear los controladores
app.MapControllers();

// Iniciar el consumidor de RabbitMQ
using (var scope = app.Services.CreateScope())
{
    var rabbitMQClient = scope.ServiceProvider.GetRequiredService<RabbitMQClient>();
    rabbitMQClient.Consume();
}

// Ejecutar la aplicación
app.Run();