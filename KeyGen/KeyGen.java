//Cyrille Lingai Dro & Ronald Choque
//CS3750
import java.io.BufferedOutputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;

public class KeyGen {

	public static void main(String[] args) {
	    SecureRandom random = new SecureRandom();
	    KeyPairGenerator generator;
		try {
			//prepare to generate RSA public/private key pair
			generator = KeyPairGenerator.getInstance("RSA");
			generator.initialize(1024, random);  //1024: key size in bits
			
			// This is for XKey
		    KeyPair pairX = generator.generateKeyPair();
		    Key pubKeyX = pairX.getPublic();
			Key privKeyX = pairX.getPrivate();
			
			//get the parameters of the keys: modulus and exponent, so we can save to file
		    KeyFactory factory = KeyFactory.getInstance("RSA");
		    RSAPublicKeySpec pubKSpecX = factory.getKeySpec(pubKeyX, 
		        RSAPublicKeySpec.class);
		    RSAPrivateKeySpec privKSpecX = factory.getKeySpec(privKeyX, 
		        RSAPrivateKeySpec.class);
		    
		    //save the parameters of the keys to the files
		    saveToRSAKeyFile("XPublic.key", pubKSpecX.getModulus(), 
		        pubKSpecX.getPublicExponent());
		    saveToRSAKeyFile("XPrivate.key", privKSpecX.getModulus(), 
		        privKSpecX.getPrivateExponent());
		    
		    // This is for YKey
		    KeyPair pairY = generator.generateKeyPair();
		    Key pubKeyY = pairY.getPublic();
			Key privKeyY = pairY.getPrivate();
			
			//get the parameters of the keys: modulus and exponet
		    RSAPublicKeySpec pubKSpecY = factory.getKeySpec(pubKeyY, 
		        RSAPublicKeySpec.class);
		    RSAPrivateKeySpec privKSpecY = factory.getKeySpec(privKeyY, 
		        RSAPrivateKeySpec.class);
		    
		    //save the parameters of the keys to the files
		    saveToRSAKeyFile("YPublic.key", pubKSpecY.getModulus(), 
		        pubKSpecY.getPublicExponent());
		    saveToRSAKeyFile("YPrivate.key", privKSpecY.getModulus(), 
		        privKSpecY.getPrivateExponent());
		    
		    
		    //Generate and save symmetric key to file
		    String symKeyStr = "1yh376dfr9la0ei6"; //16char
		    saveToSymmetricKeyFile(symKeyStr);
		    
		    System.out.println("Done!");
		   
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (InvalidKeySpecException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		}
	}
	
	//save the prameters of the public and private keys to file
	public static void saveToRSAKeyFile(String fileName,
	        BigInteger mod, BigInteger exp) throws IOException {
  
	    System.out.println("Write to " + fileName + ": modulus = " + 
	        mod.toString() + ", exponent = " + exp.toString() + "\n");
	    ObjectOutputStream oout = new ObjectOutputStream(
	      new BufferedOutputStream(new FileOutputStream(fileName)));
	    try {
	      oout.writeObject(mod);
	      oout.writeObject(exp);
	    } catch (Exception e) {
	      throw new IOException("Unexpected error", e);
	    } finally {
	      oout.close();
	    }
	}
	
	//save the symmetric key to file as binary
	public static void saveToSymmetricKeyFile(String symKeyStr) throws IOException {
		BufferedOutputStream symKeyFile = new BufferedOutputStream(
	    		new FileOutputStream("symmetric.key"));
	    byte[] symKey = symKeyStr.getBytes("UTF-8"); 
	    symKeyFile.write(symKey, 0, symKey.length);
	    		
	    symKeyFile.close();
	}
}
