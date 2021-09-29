package com.PKEClient.PKEClient.Services;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;

import com.PKEClient.PKEClient.Config.SslConfiguration;
import com.PKEClient.PKEClient.Models.EncryptedResponseEntity;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.squareup.okhttp.OkHttpClient;
import com.squareup.okhttp.Request;
import com.squareup.okhttp.Response;

@Service
public class EncryptedService {

	private PrivateKey privateKey;
    private PublicKey publicKey;

    private static final String PRIVATE_KEY_STRING = "MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBAJhBgzcXBm5A0srvFFu4FsBy+LLW+X0sH/9RvP40VIGOCusY0/CqA65YXWqyQE5jQCegBmnAeVYSvK+3PU4Y1fmr1uiquE6sZB5sl96T0ka+PKzPf4oKoAi6nwLUSenj5xTFjLsFGiuMXrCpMCPImf9JBVk89TJV43Xs3DSNKoj1AgMBAAECgYBsDysCgVv2ChnRH4eSZP/4zGCIBR0C4rs+6RM6U4eaf2ZuXqulBfUg2uRKIoKTX8ubk+6ZRZqYJSo3h9SBxgyuUrTehhOqmkMDo/oa9v7aUqAKw/uoaZKHlj+3p4L3EK0ZBpz8jjs/PXJc77Lk9ZKOUY+T0AW2Fz4syMaQOiETzQJBANF5q1lntAXN2TUWkzgir+H66HyyOpMu4meaSiktU8HWmKHa0tSB/v7LTfctnMjAbrcXywmb4ddixOgJLlAjEncCQQC6Enf3gfhEEgZTEz7WG9ev/M6hym4C+FhYKbDwk+PVLMVR7sBAtfPkiHVTVAqC082E1buZMzSKWHKAQzFL7o7zAkBye0VLOmLnnSWtXuYcktB+92qh46IhmEkCCA+py2zwDgEiy/3XSCh9Rc0ZXqNGD+0yQV2kpb3awc8NZR8bit9nAkBo4TgVnoCdfbtq4BIvBQqR++FMeJmBuxGwv+8n63QkGFQwVm6vCuAqFHBtQ5WZIGFbWk2fkKkwwaHogfcrYY/ZAkEAm5ibtJx/jZdPEF9VknswFTDJl9xjIfbwtUb6GDMc0KH7v+QTBW4GsHwt/gL+kGvLOLcEdLL5rau3IC7EQT0ZYg==";
    private static final String PUBLIC_KEY_STRING =  "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCYQYM3FwZuQNLK7xRbuBbAcviy1vl9LB//Ubz+NFSBjgrrGNPwqgOuWF1qskBOY0AnoAZpwHlWEryvtz1OGNX5q9boqrhOrGQebJfek9JGvjysz3+KCqAIup8C1Enp4+cUxYy7BRorjF6wqTAjyJn/SQVZPPUyVeN17Nw0jSqI9QIDAQAB";
    
    @Autowired
    private SslConfiguration sslConfiguration;

    public void init() {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(1024);
            KeyPair pair = generator.generateKeyPair();
            privateKey = pair.getPrivate();
            publicKey = pair.getPublic();
        } catch (Exception ignored) {
        }
    }

    public void initFromStrings() {
        try{
            //X509EncodedKeySpec keySpecPublic = new X509EncodedKeySpec(decode(PUBLIC_KEY_STRING));
            PKCS8EncodedKeySpec keySpecPrivate = new PKCS8EncodedKeySpec(decode(PRIVATE_KEY_STRING));

            KeyFactory keyFactory = KeyFactory.getInstance("RSA");

           // publicKey = keyFactory.generatePublic(keySpecPublic);
            privateKey = keyFactory.generatePrivate(keySpecPrivate);
        }catch (Exception ignored){}
    }


    public void printKeys(){
        System.err.println("Public key\n"+ encode(publicKey.getEncoded()));
        System.err.println("Private key\n"+ encode(privateKey.getEncoded()));
    }

    public String encrypt(String message) throws Exception {
        byte[] messageToBytes = message.getBytes();
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] encryptedBytes = cipher.doFinal(messageToBytes);
        return encode(encryptedBytes);
    }

    private static String encode(byte[] data) {
        return Base64.getEncoder().encodeToString(data);
    }
    private static byte[] decode(String data) {
        return Base64.getDecoder().decode(data);
    }

    public byte[] decrypt(String encryptedMessage) throws Exception {
        byte[] encryptedBytes = decode(encryptedMessage);
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] decryptedMessage = cipher.doFinal(encryptedBytes);
        /*
        return new String(decryptedMessage, "UTF8");
        */
        return decryptedMessage;
    }


    public void getDecryptedMessage() {
        EncryptedService rsa = new EncryptedService();
        rsa.initFromStrings();

        try{
        	
        	ResponseEntity<String> response = 
        		      sslConfiguration.restTemplate().getForEntity("https://localhost:8443/users/allUsers?access_token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE2MzI4NDc5NzQsInVzZXJfbmFtZSI6IjEiLCJhdXRob3JpdGllcyI6WyJST0xFX0FETUlOIl0sImp0aSI6ImQ3MGMwYjVlLTExMGEtNDFhMi05ZjU0LWRkMjk4YzhhNGU4ZSIsImNsaWVudF9pZCI6ImhlbmRpLWNsaWVudCIsInNjb3BlIjpbInJlYWQiLCJ3cml0ZSIsInRydXN0Il19.YJmZFRV1eZdsE9f6IPqz5wwa_Qn7l-5D1UTpfm8dKpg", String.class);
        	
        	/*
            OkHttpClient client = new OkHttpClient();
            Request request = new Request.Builder()
                    .url("http://localhost:8080/users/allUsers?access_token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE2MzI3MzA2OTEsInVzZXJfbmFtZSI6IjEiLCJhdXRob3JpdGllcyI6WyJST0xFX0FETUlOIl0sImp0aSI6IjYyMjEzMGM3LWZjNTAtNDQzZC1iOGY4LWFhZGYzODY1ODJjZCIsImNsaWVudF9pZCI6ImhlbmRpLWNsaWVudCIsInNjb3BlIjpbInJlYWQiLCJ3cml0ZSIsInRydXN0Il19.C2nc_JU-vU3D3TweyVIo4z3XAwQOk6PDZne5RFg108s")
                    .method("GET",null)
                    .build();
            

            Response response = client.newCall(request).execute();
            */
            
            String encryptedResponseBody = response.getBody().toString();
            
            EncryptedResponseEntity encryptedResponse = new ObjectMapper().readValue(encryptedResponseBody, EncryptedResponseEntity.class);
            
            byte[] AESPublicKey = rsa.decrypt(encryptedResponse.getRSAEncryptedPublicKey());
            
            SecretKey originalKey = new SecretKeySpec(AESPublicKey, 0, AESPublicKey.length, "AES");
            Cipher aesCipher = Cipher.getInstance("AES");
            aesCipher.init(Cipher.DECRYPT_MODE, originalKey);
            byte[] bytePlainText = aesCipher.doFinal(decode(encryptedResponse.getAESEncryptedData()));
            String plainText = new String(bytePlainText);
            
            System.err.println("SECRET MESSAGE = " + plainText);

        }catch (Exception ignored){
        	System.out.println(ignored);
        }

    }
	
}
