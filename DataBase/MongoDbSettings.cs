namespace ms_auth.DataBase
{
  /// <summary>
  /// Configuraciones para la conexión a la base de datos MongoDB.
  /// </summary>
  public class MongoDbSettings
  {
    /// <summary>
    /// Cadena de conexión a la base de datos MongoDB.
    /// </summary>
    public string ConnectionString { get; set; } = null!;

    /// <summary>
    /// Nombre de la base de datos MongoDB.
    /// </summary>
    public string DatabaseName { get; set; } = null!;
  }
}
