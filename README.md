##pc-2020a-1

Los archivos de código fuente que no corresponden a testing se encuentran en el directorio src, mientras que los archivos de código fuente de testing se encuentran en el directorio test. Los archivos de headers se encuentran en el directorio include.

Para generar un ejecutable a partir del código fuente proporcionado, se debe utilizar la herramienta `cmake` (al menos en su versión 2.8). Los pasos a seguir son los siguientes:
   1. mkdir build
   2. cd build
   3. cmake ..
   4. cd ..
   5. make -C build
El archivo ejecutable se genera en la ubicación build/src . Para ejecutarlo, se debe ejecutar
    ./build/src/socks5d

Las distintas opciones de ejecución se encuentran detalladas en el manual provisto por la cátedra.