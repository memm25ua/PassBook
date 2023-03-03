# PassBook
#### Memoria de la práctica SDS - Gestor de contraseñas - 2023
##### Autor: Madani El Mrabet Martinez

## Introducción
En esta práctica se ha desarrollado un gestor de contraseñas que permite almacenar y gestionar contraseñas de forma segura.

## Desarrollo
### Cliente y servidor HTTPS, MTLS
Para la comunicación entre el cliente y el servidor se ha utilizado el protocolo HTTPS. Para la autenticación del servidor se ha utilizado el protocolo MTLS, certificacion mutua. Para la generación de certificados se ha utilizado [CertStrap](https://github.com/square/certstrap.git), un gestor de certificados escrito en Go.