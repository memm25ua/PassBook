# PassBook
#### Memoria de la práctica SDS - Gestor de contraseñas - 2023
##### Autores: Madani El Mrabet Martinez - Jordi Cardona

## Introducción
En esta práctica se ha desarrollado un gestor de contraseñas que permite almacenar y gestionar contraseñas de forma segura.

## Desarrollo
### Cliente y servidor HTTPS, MTLS
Para la comunicación entre el cliente y el servidor se ha utilizado el protocolo HTTPS. Para la autenticación del servidor se ha utilizado el protocolo MTLS, certificacion mutua. Para la generación de certificados se ha utilizado [CertStrap](https://github.com/square/certstrap.git), un gestor de certificados escrito en Go.

## Implementaciones opcionales que haremos
- Optimización de la privacidad (conocimiento cero: el servidor sólo recibe datos cifrados por el cliente).
- Generación de contraseñas aleatorias y por perfiles
- Incorporación de datos adicionales (notas de texto, ficheros, etc.) en cada entrada.
