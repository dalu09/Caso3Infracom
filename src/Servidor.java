import java.io.BufferedReader;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;
import java.util.Random;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class Servidor extends Thread {
    
    public static final int PUERTO = 3400;
    String rutaOpenSSL;
    public static boolean enEjecucion = true;
    private int numeroConsultas;
    private static HashMap<String, String> tablaPaquetes = new HashMap<>();
    
    public static HashMap<String, String> obtenerTablaPaquetes() {
        return tablaPaquetes;
    }

    public Servidor(String rutaOpenSSL, HashMap<String, String> tablaPaquetes, int numeroConsultas) throws Exception {
        this.rutaOpenSSL = rutaOpenSSL;
        setTablaPaquetes(tablaPaquetes);
        this.numeroConsultas = numeroConsultas;
    }

    public static void setTablaPaquetes(HashMap<String, String> tablaPaquetes) {
        Servidor.tablaPaquetes = tablaPaquetes;
    }

    @Override
    public void run() {   
        try (ServerSocket servidorSocket = new ServerSocket(PUERTO)) {       
            System.out.println("Servidor iniciado correctamente");
            while (enEjecucion) {
                Socket clienteSocket = servidorSocket.accept();
                System.out.println("Nuevo cliente conectado: " + clienteSocket.getInetAddress());
                
                ManejadorCliente manejador = new ManejadorCliente(rutaOpenSSL, numeroConsultas, clienteSocket);
                manejador.start();
            }
        } catch (Exception e) {
            e.printStackTrace();
            System.exit(-1);
        }
    }

    public static void setContinuar(boolean continuar) {
        enEjecucion = continuar;
    }
}

class ManejadorCliente extends Thread {
    
    String rutaOpenSSL;
    String valorP;
    String valorG;
    BigInteger numeroP;
    Socket clienteSocket;
    BigInteger numeroG;
    Cipher descifradorRSA;
    Cipher cifradorRSA;
    Random generadorAleatorio = new Random();
    private int numeroConsultas;
    private static HashMap<String, String> tablaPaquetes = Servidor.obtenerTablaPaquetes();

    public ManejadorCliente(String rutaOpenSSL, int numeroConsultas, Socket clienteSocket) throws Exception {
        this.rutaOpenSSL = rutaOpenSSL;
        this.numeroConsultas = numeroConsultas;
        this.clienteSocket = clienteSocket;
    }

    public static void setTablaPaquetes(HashMap<String, String> tablaPaquetes) {
        ManejadorCliente.tablaPaquetes = tablaPaquetes;
    }

    @Override
    public void run() {   
        try {      
            System.out.println("Entramos");
            PrivateKey clavePrivada = obtenerClavePrivada();
            
            descifradorRSA = Cipher.getInstance("RSA");
            descifradorRSA.init(Cipher.DECRYPT_MODE, clavePrivada);
            cifradorRSA = Cipher.getInstance("RSA");
            cifradorRSA.init(Cipher.ENCRYPT_MODE, clavePrivada);
            PrintWriter escritorSocket = new PrintWriter(clienteSocket.getOutputStream(), true);
            BufferedReader lectorSocket = new BufferedReader(new InputStreamReader(clienteSocket.getInputStream()));

            String retoRecibido = lectorSocket.readLine();
            byte[] bytesReto = Base64.getDecoder().decode(retoRecibido);
            byte[] mensajeDescifrado = descifradorRSA.doFinal(bytesReto);
            String retoDescifrado = new String(mensajeDescifrado, "UTF-8");
            escritorSocket.println(retoDescifrado);

            String respuestaInicial = lectorSocket.readLine();
            if (respuestaInicial.equals("ERROR")) {
                System.exit(-1);
            }
            
            Tiempo tiempoGeneracionDiffie = new Tiempo();
            generarValoresPG();

            escritorSocket.println(numeroG.toString());
            escritorSocket.println(numeroP.toString());
            SecureRandom generadorSeguro = new SecureRandom();
            BigInteger valorX = new BigInteger(numeroP.bitLength() - 1, generadorSeguro);
            BigInteger valorGx = numeroG.modPow(valorX, numeroP);
            escritorSocket.println(valorGx.toString());
            System.out.println("Tiempo que tomó generar G, P y G^x es de " + tiempoGeneracionDiffie.getTiempo() + " ms");

            Signature verificadorFirma = Signature.getInstance("SHA1withRSA");
            verificadorFirma.initSign(clavePrivada);
            verificadorFirma.update(numeroG.toByteArray());
            verificadorFirma.update(numeroP.toByteArray());
            verificadorFirma.update(valorGx.toByteArray());
            byte[] firmaGenerada = verificadorFirma.sign();
            escritorSocket.println(Base64.getEncoder().encodeToString(firmaGenerada));

            String respuestaFirma = lectorSocket.readLine();
            if (respuestaFirma.equals("ERROR")) {
                System.exit(-1);
            }

            String valorGyTexto = lectorSocket.readLine();
            BigInteger valorGy = new BigInteger(valorGyTexto);
            BigInteger llaveSimetrica = valorGy.modPow(valorX, numeroP);

            MessageDigest generadorSHA = MessageDigest.getInstance("SHA-512"); 
            byte[] resumenLlave = generadorSHA.digest(llaveSimetrica.toByteArray());
            byte[] claveAES = Arrays.copyOfRange(resumenLlave, 0, 32);
            byte[] claveHMAC = Arrays.copyOfRange(resumenLlave, 32, 64);

            SecretKey llaveCifradoAES = new SecretKeySpec(claveAES, "AES");

            byte[] vectorInicializacion = new byte[16];
            generadorAleatorio.nextBytes(vectorInicializacion);
            IvParameterSpec ivSpec = new IvParameterSpec(vectorInicializacion);
            escritorSocket.println(Base64.getEncoder().encodeToString(vectorInicializacion));

            Cipher cifradorAES = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cifradorAES.init(Cipher.ENCRYPT_MODE, llaveCifradoAES, ivSpec);
            Cipher descifradorAES = Cipher.getInstance("AES/CBC/PKCS5Padding");
            descifradorAES.init(Cipher.DECRYPT_MODE, llaveCifradoAES, ivSpec);

            Mac generadorMAC = Mac.getInstance("HmacSHA384");
            SecretKey claveMAC = new SecretKeySpec(claveHMAC, "HmacSHA384");
            generadorMAC.init(claveMAC);

            for (int i = 0; i < numeroConsultas; i++) {
                boolean consultaCorrecta = true;
                String usuario = "";
                String paquete = "";
                Tiempo tiempoVerificacion = new Tiempo();
                String solicitudUsuario = lectorSocket.readLine();

                byte[] datosUsuario = Base64.getDecoder().decode(solicitudUsuario);
                byte[] usuarioDescifrado = descifradorAES.doFinal(datosUsuario);
                String hmacUsuario = lectorSocket.readLine();
                byte[] hmacUsuarioBytes = generadorMAC.doFinal(usuarioDescifrado);
                String compUsuario1 = new String(hmacUsuarioBytes, StandardCharsets.UTF_8);
                String compUsuario2 = new String(Base64.getDecoder().decode(hmacUsuario), StandardCharsets.UTF_8);
                if (!compUsuario1.equals(compUsuario2)) {
                    System.out.println("Error en verificación de usuario");
                    consultaCorrecta = false;
                } else {
                    usuario = new String(usuarioDescifrado, "UTF-8");
                }
                
                String solicitudPaquete = lectorSocket.readLine();
                byte[] paqueteDescifrado = descifradorAES.doFinal(Base64.getDecoder().decode(solicitudPaquete));
                String hmacPaquete = lectorSocket.readLine();
                byte[] hmacPaqueteBytes = generadorMAC.doFinal(paqueteDescifrado);
                String compPaquete1 = new String(hmacPaqueteBytes, StandardCharsets.UTF_8);
                String compPaquete2 = new String(Base64.getDecoder().decode(hmacPaquete), StandardCharsets.UTF_8);

                if (!compPaquete1.equals(compPaquete2)) {
                    System.out.println("Error en verificación de paquete");
                    consultaCorrecta = false;
                } else {
                    paquete = new String(paqueteDescifrado, "UTF-8");
                }

                System.out.println("Tiempo que tomó verificar la consulta del cliente es de " + tiempoVerificacion.getTiempoNs() + " ms");
                String claveAcceso = usuario + "," + paquete;
                String estadoPaquete = tablaPaquetes.getOrDefault(claveAcceso, "DESCONOCIDO");
                Tiempo tiempoCifrado = new Tiempo();
                byte[] estadoBytes = estadoPaquete.getBytes("UTF-8");
                byte[] estadoCifrado = cifradorAES.doFinal(estadoBytes);
                escritorSocket.println(Base64.getEncoder().encodeToString(estadoCifrado));
                System.out.println("Tiempo que tomó cifrar el estado del paquete es de " + tiempoCifrado.getTiempoNs() + " ms");
                if (!consultaCorrecta) System.out.println("Error en consulta");
            }

            String numeroCliente = lectorSocket.readLine();
            String mensajeFinalizacion = lectorSocket.readLine();
            if (!mensajeFinalizacion.equals("TERMINAR")) System.out.println("No se finalizó la conexión");
            else System.out.println("Conexión finalizada con el cliente " + numeroCliente);

            clienteSocket.close();
            escritorSocket.close();
            lectorSocket.close();
        } catch (Exception e) {
            e.printStackTrace();
            System.exit(-1);
        }
    }

    public static PublicKey obtenerClavePublica() throws FileNotFoundException {
        FileReader lectorArchivo = new FileReader("D:\\Biblioteca\\Escritorio\\nuevodef\\Caso3Infracom\\llaves/llave_pub.txt");
        BufferedReader lectorBuffer = new BufferedReader(lectorArchivo);
        PublicKey clavePublica = null;
        try {
            String claveTexto = lectorBuffer.readLine();
            byte[] claveBytes = Base64.getDecoder().decode(claveTexto);
            X509EncodedKeySpec especificacionClave = new X509EncodedKeySpec(claveBytes);
            KeyFactory fabricaClaves = KeyFactory.getInstance("RSA");
            clavePublica = fabricaClaves.generatePublic(especificacionClave);
            lectorBuffer.close();
        } catch (Exception ex) {
            ex.printStackTrace();
        }
        return clavePublica;
    }

    public static PrivateKey obtenerClavePrivada() throws FileNotFoundException {
        FileReader lectorArchivo = new FileReader("D:\\Biblioteca\\Escritorio\\nuevodef\\Caso3Infracom\\llaves/llave_priv.txt");
        BufferedReader lectorBuffer = new BufferedReader(lectorArchivo);
        PrivateKey clavePrivada = null;
        try {
            String claveTexto = lectorBuffer.readLine();
            byte[] claveBytes = Base64.getDecoder().decode(claveTexto);
            PKCS8EncodedKeySpec especificacionClave = new PKCS8EncodedKeySpec(claveBytes);
            KeyFactory fabricaClaves = KeyFactory.getInstance("RSA");
            clavePrivada = fabricaClaves.generatePrivate(especificacionClave);
            lectorBuffer.close();
        } catch (Exception ex) {
            ex.printStackTrace();
        }
        return clavePrivada;
    }

    public void generarValoresPG() throws Exception {
        Process proceso = Runtime.getRuntime().exec(rutaOpenSSL + "\\openssl dhparam -text 1024");
        BufferedReader lectorError = new BufferedReader(new InputStreamReader(proceso.getErrorStream()));
        BufferedReader lectorProceso = new BufferedReader(new InputStreamReader(proceso.getInputStream()));
        String error = lectorError.readLine();
        while (error != null) error = lectorError.readLine();
        String linea;
        StringBuilder salidaProceso = new StringBuilder();
        while ((linea = lectorProceso.readLine()) != null) {
            salidaProceso.append(linea).append("\n");
        }
        lectorProceso.close();
        lectorError.close();
        proceso.waitFor();
        String salidaTexto = salidaProceso.toString();
        Pattern patronPrime = Pattern.compile("prime:\\s+([\\s\\S]+?)generator:");
        Pattern patronGenerador = Pattern.compile("generator:\\s+(\\d+)");
        Matcher matcherPrime = patronPrime.matcher(salidaTexto);
        if (matcherPrime.find()) {
            this.valorP = matcherPrime.group(1).replaceAll("\\s+", "");
        }
        Matcher matcherGenerador = patronGenerador.matcher(salidaTexto);
        if (matcherGenerador.find()) {
            this.valorG = matcherGenerador.group(1);
        }
        String valorPHex = this.valorP.replace(":", "").replaceAll("\\s", "");
        this.numeroP = new BigInteger(valorPHex, 16);
        this.numeroG = new BigInteger(valorG);
    }
}