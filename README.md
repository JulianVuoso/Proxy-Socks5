##pc-2020a-1

Los archivos de código fuente que no corresponden a testing se encuentran en el directorio src, mientras que los archivos de código fuente de testing se encuentran en el directorio test. Los archivos de headers se encuentran en el directorio include.

Para generar un ejecutable a partir del código fuente proporcionado, se debe utilizar la herramienta `cmake` (al menos en su versión 2.8). Los pasos a seguir son los siguientes:

1. `mkdir build`
2. `cd build`
3. `cmake ..`
4. `cd ..`
5. `make -C build clean all`

Si se desea limpiar todos los archivos generados al compilar, correr
    `make -C build clean`
El archivo ejecutable del proxy socks se genera en la ubicación build/src . Para ejecutarlo, se debe ejecutar
    `./build/src/socks5d`
Las distintas opciones de ejecución se encuentran detalladas en el manual socks5d, ubicado en la carpeta root. Para abrirlo, ejecutar
    `man ./socks5d.8`

El archivo ejecutable del cliente de nuestro protocolo para monitoreo y configuración del proxy se genera en la ubicación build/src . Para ejecutarlo, se debe ejecutar
    `./build/src/client`
Las distintas opciones de ejecución se encuentran detalladas en el manual client, ubicado en la carpeta root. Para abrirlo, ejecutar
    `man ./client.8`

Para el desarrollo de la aplicación, además de los códigos subidos por la cátedra, utilizamos un fragmento de código del sitio 
    https://nachtimwald.com/2017/11/18/base64-encode-and-decode-in-c/
Dentro del sitio, se aclara que todo el código posteado allí está licenciado bajo licencia MIT (que es una licencia OSI). Esto se utilizó para decodificar las credenciales en caso de venir codificadas en basic en un header Authentication para HTTP.