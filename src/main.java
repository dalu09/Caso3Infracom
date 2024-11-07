import java.io.BufferedReader;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;

public class main {
    static boolean enEjecucion = true;
    static HashMap<String, String> tablaPaquetes = new HashMap<>();
    static ArrayList<String> listaUsuarios = new ArrayList<>();

    public static void main(String[] args) throws Exception {
        FileReader lectorArchivo = new FileReader("C:\\Users\\dluci\\OneDrive\\Documentos\\GitHub\\Caso3Infracom\\infopaquetes.txt");
        BufferedReader lectorPaquetes = new BufferedReader(lectorArchivo);
        String lineaInfo = lectorPaquetes.readLine();
        while (lineaInfo != null) {
            String[] datosSeparados = lineaInfo.split(",");
            String datosUsuario = datosSeparados[0] + "," + datosSeparados[1];
            listaUsuarios.add(datosUsuario);
            tablaPaquetes.put(datosUsuario, datosSeparados[2]);
            lineaInfo = lectorPaquetes.readLine();
        }
        lectorPaquetes.close();
        BufferedReader lectorConsola = new BufferedReader(new InputStreamReader(System.in));
        System.out.println("Escriba la ruta completa de la ubicación de openssl:");
        String rutaOpenSSL = "C:\\Users\\dluci\\OneDrive\\Documentos\\GitHub\\Caso3Infracom\\Lib\\OpenSSL";
        while (enEjecucion) {
            System.out.println("--------------Bienvenido al menú principal del caso 3----------------");
            System.out.println("Selecciona una de las siguientes opciones:");
            System.out.println("1. Opción 1. Generar las llaves.");
            System.out.println("2. Opción 2 simétrico.");
            System.out.println("3. Opción 2 asimétrico.");
            System.out.println("4. Salir");

            String respuesta = lectorConsola.readLine();
            if (respuesta.equals("1")) {
                generarLlavesASM();
                System.out.println("Funcionando, revisa la carpeta llaves, se han generado.");
            } else if (respuesta.equals("2")) {
                Tiempo tiempoTotal = new Tiempo();
                System.out.println("Indique el número de clientes concurrentes en la aplicación:");
                int cantidadClientes = Integer.valueOf(lectorConsola.readLine());
                int cantidadConsultas = 1;
                if (cantidadClientes == 1) cantidadConsultas = 32;

                Servidor servidor = new Servidor(rutaOpenSSL, tablaPaquetes, cantidadConsultas);
                servidor.start();

                Thread.sleep(50);
                Cliente[] clientes = new Cliente[cantidadClientes];
                for (int i = 0; i < cantidadClientes; i++) {
                    clientes[i] = new Cliente(i, listaUsuarios, cantidadConsultas);
                    clientes[i].start();
                }
                for (int j = 0; j < cantidadClientes; j++) {
                    clientes[j].join();
                }
                Servidor.setContinuar(false);

                System.out.println("El tiempo del procedimiento fue " + tiempoTotal.getTiempo() + " ms");
            } else if (respuesta.equals("3")) {
                Tiempo tiempoTotalASM = new Tiempo();
                System.out.println("Indique el número de clientes concurrentes en la aplicación:");
                int cantidadClientes = Integer.valueOf(lectorConsola.readLine());
                int cantidadConsultas = 1;
                if (cantidadClientes == 1) cantidadConsultas = 32;

                ServidorAsmet servidorASM = new ServidorAsmet(rutaOpenSSL, tablaPaquetes, cantidadConsultas);
                servidorASM.start();

                Thread.sleep(50);
                ClienteAsmet[] clientesASM = new ClienteAsmet[cantidadClientes];
                for (int i = 0; i < cantidadClientes; i++) {
                    clientesASM[i] = new ClienteAsmet(i, listaUsuarios, cantidadConsultas);
                    clientesASM[i].start();
                }
                for (int j = 0; j < cantidadClientes; j++) {
                    clientesASM[j].join();
                }
                ServidorAsmet.setContinuar(false);

                System.out.println("Realizar todo el procedimiento tomó " + tiempoTotalASM.getTiempo() + " ms");
            } else if (respuesta.equals("4")) {
                enEjecucion = false;
            }
        }
    }

    public static void generarLlavesASM() throws NoSuchAlgorithmException {
        
        KeyPairGenerator generadorLlaves = KeyPairGenerator.getInstance("RSA");
        generadorLlaves.initialize(1024);
        KeyPair parLlaves = generadorLlaves.generateKeyPair();
        
         
    
        Tiempo tiempoClavePrivada = new Tiempo();
        PrivateKey clavePrivada = parLlaves.getPrivate();
        String clavePrivadaTexto = Base64.getEncoder().encodeToString(clavePrivada.getEncoded());
        try {
            FileWriter archivoPrivado = new FileWriter("C:\\Users\\dluci\\OneDrive\\Documentos\\GitHub\\Caso3Infracom\\llaves\\llave_priv.txt");
            archivoPrivado.write(clavePrivadaTexto);
            archivoPrivado.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
        long tiempoGeneracionClavePrivada = tiempoClavePrivada.getTiempo();

        Tiempo tiempoClavePublica = new Tiempo();
        PublicKey clavePublica = parLlaves.getPublic();
        String clavePublicaTexto = Base64.getEncoder().encodeToString(clavePublica.getEncoded());
        try {
            FileWriter archivoPublico = new FileWriter("C:\\Users\\dluci\\OneDrive\\Documentos\\GitHub\\Caso3Infracom\\llaves\\llave_pub.txt");
            archivoPublico.write(clavePublicaTexto);
            archivoPublico.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
        long tiempoGeneracionClavePublica = tiempoClavePublica.getTiempo();

        System.out.println("El tiempo de extracción de la clave pública fue: " + tiempoGeneracionClavePublica + " ms");
        System.out.println("El tiempo de extracción de la clave privada fue: " + tiempoGeneracionClavePrivada + " ms");
    }
}