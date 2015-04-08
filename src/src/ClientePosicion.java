package src;

import java.io.*;
import java.math.BigInteger;
import java.net.Socket;
import java.security.*;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Date;

import org.bouncycastle.x509.X509V1CertificateGenerator;

import javax.crypto.*;
import javax.security.auth.x500.X500Principal;

public class ClientePosicion {
	/**
	 * Constantes.
	 */
	static String DIRSERV = "infracomp.virtual.uniandes.edu.co";
	static int PUERTO = 80;
	static String INIC = "HOLA";
	static String ALG = "ALGORITMOS";
	static String CERTIFICADO = "CERCLNT";
	static String ALGS = "AES";
	static String ALGA = "RSA";
	static String ALGD = "HMACSHA1";
	static String SG = ":";
	static KeyPair keypair;

	/**
	 * Variables.
	 */
	static Socket comunicacion;
	static PrintWriter writer;
	static BufferedReader reader;
	static X509Certificate certServer = null;

	/**
	 * Codigo.
	 * @param args
	 */
	public static void main(String args[]){
		try{
			//Inicializacion de las llaves.
			KeyPairGenerator generator = KeyPairGenerator.getInstance(ALGA);
			generator.initialize(1024);
			keypair = generator.generateKeyPair();
			//Inicializacion de los sockets
			comunicacion = new Socket("localhost", PUERTO);
			writer = new PrintWriter(comunicacion.getOutputStream(), true);
			reader = new BufferedReader(new InputStreamReader(comunicacion.getInputStream()));
			//HOLA
			writer.println( INIC );
			//INICIO
			System.out.println(reader.readLine());
			//ALGORITMOS:ALGS:ALGA:ALGD
			writer.println( ALG + SG + ALGS + SG + ALGA + SG + ALGD);
			if(reader.ready()) System.out.println(reader.readLine());
			//ESTADO:OK|ERROR
			System.out.println(reader.readLine());
			//CERCLNT
			writer.println( CERTIFICADO );
			//FLUJO DE BYTES DEL CERTIFICADO
			X509Certificate cert = certificado();
			byte[] certb = cert.getEncoded();
			comunicacion.getOutputStream().write(certb);
			comunicacion.getOutputStream().flush();
			//CERSRV
			System.out.println(reader.readLine());
			//FLUJO DE BYTES DEL CERTIFICADO
			//INIT
			//ACTV
			//ACT2
			//RTA:OK|ERROR
		}catch(IOException e){
			System.out.println("Error en la conexion con el servidor: "+e.getMessage());
		} catch (CertificateEncodingException e) {
			System.out.println("Error en el certificado: "+e.getMessage());
		} catch (NoSuchAlgorithmException e) {
			System.out.println("Error en generando las llaves: "+e.getMessage());
		} catch (InvalidKeyException | IllegalStateException | NoSuchProviderException | SignatureException e) {
			System.out.println("Error firmando el certificado " + e.getMessage());
		}finally{
			try {
				comunicacion.close();
				writer.close();
				reader.close();
			} catch (IOException e) {
				System.out.println("No se pudo cerrar la conexion." + e.getMessage());
			}
		}
	}

	public static X509Certificate certificado() throws CertificateEncodingException, InvalidKeyException, IllegalStateException, NoSuchProviderException, NoSuchAlgorithmException, SignatureException{
		Date startDate = new Date (System.nanoTime());
		Date expiryDate = new Date (System.nanoTime() + 999999999);
		BigInteger serialNumber = new BigInteger("1909199426091995");
		X509V1CertificateGenerator certGen = new X509V1CertificateGenerator();
		X500Principal dnName = new X500Principal("CN=Test CA Certificate");
		certGen.setSerialNumber(serialNumber);
		certGen.setIssuerDN(dnName);
		certGen.setNotBefore(startDate);
		certGen.setNotAfter(expiryDate);
		certGen.setSubjectDN(dnName);
		certGen.setPublicKey(keypair.getPublic());
		certGen.setSignatureAlgorithm(ALGA);
		X509Certificate cert  = certGen.generate(keypair.getPrivate(), "BC");
		return cert;
	}
}
