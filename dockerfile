# Usa la imagen oficial de .NET SDK para compilar la aplicación
FROM mcr.microsoft.com/dotnet/sdk:9.0 AS build
WORKDIR /app

# Copia el archivo de proyecto y restaura las dependencias
COPY *.csproj ./
RUN dotnet restore

# Copia el resto de los archivos de la aplicación y compila
COPY . ./
RUN dotnet publish -c Release -o out

# Usa la imagen oficial de .NET Runtime para ejecutar la aplicación
FROM mcr.microsoft.com/dotnet/aspnet:9.0 AS runtime
WORKDIR /app
COPY --from=build /app/out .

# Definir variables de entorno
ENV JWT_ISSUER="${JWT_ISSUER}"
ENV JWT_AUDIENCE="${JWT_AUDIENCE}"
ENV JWT_KEY="${JWT_KEY}"
ENV MONGO_CONNECTION_STRING="${MONGO_CONNECTION_STRING}"
ENV MONGO_DATABASE_NAME="${MONGO_DATABASE_NAME}"
ENV EMAIL_SMTP_SERVER="${EMAIL_SMTP_SERVER}"
ENV EMAIL_SMTP_PORT="${EMAIL_SMTP_PORT}"
ENV EMAIL_SMTP_USER="${EMAIL_SMTP_USER}"
ENV EMAIL_SMTP_PASSWORD="${EMAIL_SMTP_PASSWORD}"
ENV EMAIL_SMTP_APP_NAME="${EMAIL_SMTP_APP_NAME}"

# Exponer el puerto en el que la aplicación escuchará
EXPOSE 8080

# Configura el punto de entrada para ejecutar la aplicación
ENTRYPOINT ["dotnet", "ms_auth.dll"]