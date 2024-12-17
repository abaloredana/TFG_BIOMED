##Instrucciones para ejecutar un ataque de chipwhisperer con diferentes visualizaciones de valores intermedios (sumden1 y sumden2) para el analisis de la varianza.

** graphs_sumden_vs_trace_index_overlapping_bnum.py: **

    Al ejecutar este script (python graphs_sumden_vs_trace_index_overlapping_bnum.py), se realizará el ataque como siempre, imprimiendo por consola la tabla de resulatdos del ataque. 
    Adicionalmente se creará una carpeta dentro del directorio en el cual se ejecute el codigo llamado "graphs". Dentro de esta carpeta se encontrarán las gráficas para sumden1 (gráfico de linea) y sumden2 (heatmap). Ambos tipos de gráficos se almacenan como png, pero al momento de ejecutar el código se podrá visualizar interactivamente cada uno. Cada gráfica se llama segun su tipo y termina en un número que se corresponde con el número de trazas utilizadas para su ataque correspondiente.

        -Sumden1: Existirá una gráfica por cada Byte de subclave (bnum) y una gráfica global    donde los resultados the cada bnum se superponen.

        -Sumden2: Existirá un heatmap por cada Byte de subclave (bnum)

    Antes de ejecutar este script se debe acceder al código y sustituir el valor de la variable "project_file" por el path que lleve al archivo que contiene las trazas necesarias para el ataque. De igual manera, la variable "numTraces" debe ser modificada manualmente para asignarle el numero de trazas con el que se esté realizando el ataque (este valor debe coincidir con el de la variable numTraces del archivo de configuración dentro de los datos (traces), en caso contrario las gráficas no tendrán coherencia)

    Importante resaltar que, tras la creación de las gráficas para un archivo de datos (traces) y numTraces especifico, ejecutar nuevamente el código para la misma combinación de variables hará que no se editen las gráficas ya existentes y por ende no se podrá visualizar la version interactiva de las gráficas (para hacer zoom y demás). Para solucionar esto, entrar en el código y modificar el nombre de las gráficas para que no coincida con las ya existentes o simplemente borrar las gráficas anteriores de la carpeta "graphs"

** run_cpa_attack_console_output.py: **

     Al ejecutar este script (python graphs_sumden_vs_trace_index_overlapping_bnum.py), se realizará el ataque como siempre, imprimiendo por consola la tabla de resulatdos del ataque. 
     Adicionalmente se visualizarán por consola los valores intermedios explicitos de cada par (sumden1 y sumden2), acompañados por su respectivo bnum. Al añadirse trazas progresivamente al ataque, deberían existir varios pares valores intermedios (256) por cada bnum.


