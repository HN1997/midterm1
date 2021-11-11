package isp.secrecy;

import fri.isp.Agent;
import fri.isp.Environment;

import javax.crypto.KeyGenerator;
import java.security.Key;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.ChaCha20ParameterSpec;
import java.security.SecureRandom;

/**
 * TASK:
 * Assuming Alice and Bob know a shared secret key in advance, secure the channel using
 * ChaCha20 stream cipher. Then exchange ten messages between Alice and Bob.
 * <p>
 * https://docs.oracle.com/en/java/javase/11/docs/api/java.base/javax/crypto/Cipher.html
 */
public class A3ChaCha20 {
    public static void main(String[] args) throws Exception {
    	
    	System.out.println("ChaCha20 : \n");
    	
        // STEP 1: Alice and Bob beforehand agree upon a cipher algorithm and a shared secret key
        // This key may be accessed as a global variable by both agents
    	//Key must be 256 bits
    	KeyGenerator keyGen = KeyGenerator.getInstance("AES");
    	keyGen.init(256); 
    	SecretKey key = keyGen.generateKey();
        
        //Creating a random nonce, that needs to have 12 bytes
        byte[] nonce = new byte[12];
        new SecureRandom().nextBytes(nonce);
        
        //Counter 
        int counter = 1;

        // STEP 2: Setup communication
        final Environment env = new Environment();

        env.add(new Agent("alice") {
            @Override
            public void task() throws Exception {
            	
            	//10 times
            	for(int i=1; i<=10; i++)
            	{
                    final String message = "I love you Bob x"+i+ " times. Kisses, Alice.";
                    /* TODO STEP 3:
                     * Alice creates, encrypts and sends a message to Bob. Bob replies to the message.
                     * Such exchange repeats 10 times.
                     *
                     * Recall, ChaCha2 requires that you specify the nonce and the counter explicitly.
                     */
                    
                    ///////////// Sending /////////////
                    byte[] ciphertextBytes = encryptChacha20(message.getBytes(), key, nonce, counter);
                    send("bob", ciphertextBytes);
                    
                	////////////// Receiving //////////////
                    byte[] cipherText = receive("bob");
                    byte[] plainText = decryptChaCha20(cipherText, key, nonce, counter);
                    print("Got : '%s'", new String(plainText));
            	}
            }
        });

        env.add(new Agent("bob") {
            @Override
            public void task() throws Exception {

            	//10 times
            	for(int i=1; i<=10; i++)
            	{
                	////////////// Receiving //////////////
                    byte[] cipherText = receive("alice");
                    byte[] plainText = decryptChaCha20(cipherText, key, nonce, counter);
                    print("Got : '%s'", new String(plainText));
                    
                    ///////////// Sending /////////////
                    final String message = "I love you too Alice x"+i+" times. Bob.";
                    byte[] ciphertextBytes = encryptChacha20(message.getBytes(), key, nonce, counter);
                    send("alice", ciphertextBytes);
            	}
            }
        });

        env.connect("alice", "bob");
        env.start();
    }
    
    //Function to encrpyt a plaintext with ChaCha20, returns the ciphertext
    public static byte[] encryptChacha20(byte[] plainText, Key key, byte[] nonce, int counter) throws Exception {
        Cipher cipher = Cipher.getInstance("ChaCha20"); //Initialize the cipher for chacha20
        ChaCha20ParameterSpec chacha20ParameterSpec = new ChaCha20ParameterSpec(nonce, counter); //Specify nonce and counter
        cipher.init(Cipher.ENCRYPT_MODE, key, chacha20ParameterSpec); //Initialize the cipher as encryption mode, with the key and param (counter + nonce)
        return cipher.doFinal(plainText); //Return the encrypted plaintext
    }

    //Function to decrypt a ciphertext with ChaCha20, returns the plain text
    public static byte[] decryptChaCha20(byte[] cipherText, Key key, byte[] nonce, int counter) throws Exception {
        Cipher cipher = Cipher.getInstance("ChaCha20"); //Initialize the cipher for chacha20
        ChaCha20ParameterSpec chacha20ParameterSpec = new ChaCha20ParameterSpec(nonce, counter); //Specify nonce and counter
        cipher.init(Cipher.DECRYPT_MODE, key, chacha20ParameterSpec); //Initialize the cipher as decryption mode, with the key and param (counter + nonce)
        return cipher.doFinal(cipherText); //Return the decrypted ciphertext
    }
}
