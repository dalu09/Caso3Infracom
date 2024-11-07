import java.io.BufferedReader;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.net.Socket;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Random;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class Cliente extends Thread {

    public static final int PUERTO = 3400;
    public static final String DIRECCION_SERVIDOR = "localhost";
    public static Random generadorAleatorio = new Random();
    public int idCliente;
    private ArrayList<String> listaUsuarios;
    private int numeroConsultas;

    public Cliente(int idCliente, ArrayList<String> listaUsuarios, int numeroConsultas) {
        this.idCliente = idCliente;
        this.listaUsuarios = listaUsuarios;
        this.numeroConsultas = numeroConsultas;
    }

    @Override
    public void run() {
        try {
            Socket conexionSocket = null;
            PrintWriter escritorSocket = null;
            BufferedReader lectorSocket = null;

            System.out.println("Iniciando cliente " + idCliente);
            PublicKey clavePublicaServidor = obtenerClavePublica();
            BigInteger numeroReto = BigInteger.probablePrime(118, generadorAleatorio);
            Cipher cifradorRSA = Cipher.getInstance("RSA");
            cifradorRSA.init(Cipher.ENCRYPT_MODE, clavePublicaServidor);
            Cipher descifradorRSA = Cipher.getInstance("RSA");
            descifradorRSA.init(Cipher.DECRYPT_MODE, clavePublicaServidor);

            String retoComoTexto = numeroReto.toString();
            byte[] retoEnBytes = retoComoTexto.getBytes("UTF-8");
            byte[] retoCifrado = cifradorRSA.doFinal(retoEnBytes);

            conexionSocket = new Socket(DIRECCION_SERVIDOR, PUERTO);
            System.out.println("Enviando solicitud al servidor");
            escritorSocket = new PrintWriter(conexionSocket.getOutputStream(), true);
            lectorSocket = new BufferedReader(new InputStreamReader(conexionSocket.getInputStream()));

            escritorSocket.println(Base64.getEncoder().encodeToString(retoCifrado));
            String respuestaReto = lectorSocket.readLine();

            if (retoComoTexto.equals(respuestaReto)) {
                System.out.println("Servidor autenticado correctamente. Continuando...");
                escritorSocket.println("OK");
            } else {
                System.out.println("Error de autenticación con el servidor");
                escritorSocket.println("ERROR");
                System.exit(-1);
            }

            String valorG = lectorSocket.readLine();
            String valorP = lectorSocket.readLine();
            String valorGx = lectorSocket.readLine();
            String firmaServidor = lectorSocket.readLine();

            byte[] firmaBytes = Base64.getDecoder().decode(firmaServidor);
            Signature verificadorFirma = Signature.getInstance("SHA1withRSA");
            verificadorFirma.initVerify(clavePublicaServidor);
            BigInteger numeroG = new BigInteger(valorG);
            BigInteger numeroP = new BigInteger(valorP);
            BigInteger numeroGx = new BigInteger(valorGx);
            verificadorFirma.update(numeroG.toByteArray());
            verificadorFirma.update(numeroP.toByteArray());
            verificadorFirma.update(numeroGx.toByteArray());

            if (verificadorFirma.verify(firmaBytes)) {
                System.out.println("Firma validada correctamente. Continuando...");
                escritorSocket.println("OK");
            } else {
                System.out.println("Error de validación de firma");
                escritorSocket.println("ERROR");
            }

            BigInteger numeroY = new BigInteger(numeroP.bitLength() - 1, generadorAleatorio);
            BigInteger numeroGy = numeroG.modPow(numeroY, numeroP);
            escritorSocket.println(numeroGy.toString());
            BigInteger llaveSimetrica = numeroGx.modPow(numeroY, numeroP);

            MessageDigest digestorSHA = MessageDigest.getInstance("SHA-512");
            byte[] resumenLlave = digestorSHA.digest(llaveSimetrica.toByteArray());

            byte[] llaveCifradoAES = Arrays.copyOfRange(resumenLlave, 0, 32);
            byte[] llaveMAC = Arrays.copyOfRange(resumenLlave, 32, 64);

            SecretKey claveAES = new SecretKeySpec(llaveCifradoAES, "AES");

            String ivEnTexto = lectorSocket.readLine();
            byte[] vectorInicializacion = Base64.getDecoder().decode(ivEnTexto);
            IvParameterSpec ivParameterSpec = new IvParameterSpec(vectorInicializacion);

            Cipher cifradorAES = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cifradorAES.init(Cipher.ENCRYPT_MODE, claveAES, ivParameterSpec);
            Cipher descifradorAES = Cipher.getInstance("AES/CBC/PKCS5Padding");
            descifradorAES.init(Cipher.DECRYPT_MODE, claveAES, ivParameterSpec);

            Mac generadorMAC = Mac.getInstance("HmacSHA384");
            SecretKey claveHMAC = new SecretKeySpec(llaveMAC, "HmacSHA384");
            generadorMAC.init(claveHMAC);

            for (int i = 0; i < numeroConsultas; i++) {
                System.out.println("Solicitud número: " + (i + 1) + " del cliente " + idCliente);
                int indiceUsuario = generadorAleatorio.nextInt(listaUsuarios.size() - 1);
                String informacionUsuario = listaUsuarios.get(indiceUsuario);
                String[] datosUsuario = informacionUsuario.split(",");

                byte[] usuarioBytes = datosUsuario[0].getBytes("UTF-8");
                byte[] usuarioCifrado = cifradorAES.doFinal(usuarioBytes);
                escritorSocket.println(Base64.getEncoder().encodeToString(usuarioCifrado));
                byte[] hmacUsuario = generadorMAC.doFinal(usuarioBytes);
                escritorSocket.println(Base64.getEncoder().encodeToString(hmacUsuario));

                byte[] paqueteBytes = datosUsuario[1].getBytes("UTF-8");
                byte[] paqueteCifrado = cifradorAES.doFinal(paqueteBytes);
                escritorSocket.println(Base64.getEncoder().encodeToString(paqueteCifrado));
                byte[] hmacPaquete = generadorMAC.doFinal(paqueteBytes);
                escritorSocket.println(Base64.getEncoder().encodeToString(hmacPaquete));

                String respuestaServidor = lectorSocket.readLine();
                byte[] respuestaBytes = Base64.getDecoder().decode(respuestaServidor);
                byte[] respuestaDescifrada = descifradorAES.doFinal(respuestaBytes);
                String respuestaFinal = new String(respuestaDescifrada, "UTF-8");

                if (!respuestaFinal.equals("DESCONOCIDO")) {
                    System.out.println("Consulta por " + datosUsuario[0] + " con el paquete " + datosUsuario[1] + " resultó en: " + respuestaFinal);
                }
            }

            escritorSocket.println(String.valueOf(idCliente));
            System.out.println("TERMINAR");
            escritorSocket.println("TERMINAR");

            conexionSocket.close();
            escritorSocket.close();
            lectorSocket.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static PublicKey obtenerClavePublica() throws FileNotFoundException {
        FileReader lectorArchivo = new FileReader("C:\\Users\\dluci\\OneDrive\\Documentos\\GitHub\\Caso3Infracom\\llaves/llave_pub.txt");
        BufferedReader lectorBuffer = new BufferedReader(lectorArchivo);
        PublicKey clavePublica = null;
        try {
            String clavePublicaEnTexto = lectorBuffer.readLine();
            byte[] clavePublicaBytes = Base64.getDecoder().decode(clavePublicaEnTexto);
            X509EncodedKeySpec especificacionClave = new X509EncodedKeySpec(clavePublicaBytes);
            KeyFactory fabricaClaves = KeyFactory.getInstance("RSA");
            clavePublica = fabricaClaves.generatePublic(especificacionClave);
            lectorBuffer.close();
        } catch (Exception ex) {
            ex.printStackTrace();
        }
        return clavePublica;
    }
}