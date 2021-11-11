package isp.secrecy;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

import fri.isp.Agent;

import java.security.SecureRandom;
import java.util.Random;
import java.util.concurrent.TimeUnit;



/**
 * Implement a brute force key search (exhaustive key search) if you know that the
 * message is:
 * "I would like to keep this text confidential Bob. Kind regards, Alice."
 * <p>
 * Assume the message was encrypted with "DES/ECB/PKCS5Padding".
 * Also assume that the key was poorly chosen. In particular, as an attacker,
 * you are certain that all bytes in the key, with the exception of th last three bytes,
 * have been set to 0.
 * <p>
 * The length of DES key is 8 bytes.
 * <p>
 * To manually specify a key, use the class {@link javax.crypto.spec.SecretKeySpec})
 */
public class A4ExhaustiveSearch {
    public static void main(String[] args) throws Exception {
        final String message = "I would like to keep this text confidential Bob. Kind regards, Alice.";
        System.out.println("[PT] : " + message);
        //System.out.println("[MESSAGE] " + message);
        
        //Random bytes
        byte[] byteFive = new byte[1];
        byte[] byteSix = new byte[1];
        byte[] byteSeven = new byte[1];
        new Random().nextBytes(byteFive);
        new Random().nextBytes(byteSix);
        new Random().nextBytes(byteSeven);
        
        //Printing the key needed to be found :
        System.out.println("Key generated : [0, 0, 0, 0, 0, " + byteFive[0] + ", " + byteSix[0] + ", " + byteSeven[0] + "]"); 
        
        //Table of random bytes where all bytes are 0 except the last three bytes
        byte[] keyBytes = {0,0,0,0,0,byteFive[0],byteSix[0],byteSeven[0]}; 
        
        //our key that we will try to bruteforce
        SecretKeySpec key = new SecretKeySpec(keyBytes, "DES");

        //Encryption using our random key
        Cipher encrypt = Cipher.getInstance("DES/ECB/PKCS5Padding"); //Encryption with AES in CBC and adding a padding
        encrypt.init(Cipher.ENCRYPT_MODE, key);
        byte[] encryptedMessage = encrypt.doFinal(message.getBytes()); //cipher text
        System.out.println("[CT] : " + Agent.hex(encryptedMessage));
        
        //Bruteforce to get the key
        byte[] decryptionBytes = bruteForceKey(encryptedMessage, message);
        
        //If not null, we print the plaintext using the key we discovered
        if(decryptionBytes != null)
        {
            Cipher decrypt = Cipher.getInstance("DES/ECB/PKCS5Padding"); //Encryption with AES in CBC and adding a padding
            SecretKeySpec keyDec = new SecretKeySpec(decryptionBytes, "DES");
    		decrypt.init(Cipher.DECRYPT_MODE, keyDec);
            byte[] plaintext = decrypt.doFinal(encryptedMessage); //plain text
            System.out.println("[+] Decryption with bruteforce: " + new String(plaintext));
        }

    }

    public static byte[] bruteForceKey(byte[] ct, String message) throws Exception {
        System.out.println("\n[+] Beginning of the bruteforce in 3s...");
        TimeUnit.SECONDS.sleep(3);
        
        String messageDecrypted = "";
        byte[] minimumKey = {0,0,0,0,0,0,0,0};
        
        for(int i=-128; i<=127; i++)
        {
        	for(int j=-128; j<=127; j++)
        	{
        		for(int k=-128; k<=127; k++)
        		{
        			minimumKey[5] = (byte) i;
        			minimumKey[6] = (byte) j;
        			minimumKey[7] = (byte) k;

        			//Trying to decrypt with the new key
        			try
        			{
            			Cipher decrypt = Cipher.getInstance("DES/ECB/PKCS5Padding"); //Encryption with AES in CBC and adding a padding
            	        SecretKeySpec key = new SecretKeySpec(minimumKey, "DES");
            			decrypt.init(Cipher.DECRYPT_MODE, key);
            	        byte[] plaintext = decrypt.doFinal(ct); //plain text
            	        
            	        //If we have the same plain text as the message
            	        if(new String(plaintext).equals(message))
            	        {
                    	    System.out.println("[+] Key found for decryption !");
                    	    return minimumKey;
            	        }
        			} 
        			catch(BadPaddingException e)
        			{
        				System.out.println("[-] Trying key : [" + minimumKey[0] + ", " + minimumKey[1] + ", " + minimumKey[2] + ", "
        						+ minimumKey[3] + ", " + minimumKey[4] + ", " + minimumKey[5] + ", " + minimumKey[6] + ", "
        						+ minimumKey[7] + "] : FAILED ");
        			}	
        		}
        	}
        }

        return null;
    }
    
    
}
