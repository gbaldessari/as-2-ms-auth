# Creado en .net

.env deberia tener estos parametros
JWT_KEY
JWT_ISSUER
JWT_AUDIENCE
MONGO_CONNECTION_STRING
MONGO_DATABASE_NAME
RABBITMQ_HOST
RABBITMQ_PORT
RABBITMQ_QUEUE
RABBITMQ_USERNAME
RABBITMQ_PASSWORD
RABBITMQ_VHOST
EMAIL_SMTP_SERVER
EMAIL_SMTP_PORT
EMAIL_SMTP_USER
EMAIL_SMTP_PASSWORD
EMAIL_SMTP_APP_NAME

El proyecto tiene un dockerfile por lo que para ejecutarlo hay que utilizar estos comandos

buildear imagen
docker build -t ms_auth .

Ejecutar el contenedor y exponer el puerto 5012 del contenedor al puerto 5012 de tu máquina host:
docker run -d -p 5012:5012 --env-file .env --name ms_auth_container ms_auth

Si por alguna razon esto no funciona tambien puede ser ejecutado teniendo
.net 9.0
que puede ser descargado en el siguiente enlace
<https://dotnet.microsoft.com/en-us/download>

Una vez instalado ejecutar dentro de la carpeta raiz del proyecto
dotnet run
