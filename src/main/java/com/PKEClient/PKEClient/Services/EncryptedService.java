package com.PKEClient.PKEClient.Services;

import java.io.BufferedInputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509ExtendedTrustManager;
import javax.net.ssl.X509TrustManager;


import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.Resource;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;

import com.PKEClient.PKEClient.Config.SslConfiguration;
import com.PKEClient.PKEClient.Models.EncryptedResponseEntity;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import okhttp3.CertificatePinner;
import okhttp3.MediaType;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.RequestBody;
import okhttp3.Response;


@Service
public class EncryptedService {

	private PrivateKey privateKey;
    private PublicKey publicKey;

    private static final String PRIVATE_KEY_STRING = "MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBAJhBgzcXBm5A0srvFFu4FsBy+LLW+X0sH/9RvP40VIGOCusY0/CqA65YXWqyQE5jQCegBmnAeVYSvK+3PU4Y1fmr1uiquE6sZB5sl96T0ka+PKzPf4oKoAi6nwLUSenj5xTFjLsFGiuMXrCpMCPImf9JBVk89TJV43Xs3DSNKoj1AgMBAAECgYBsDysCgVv2ChnRH4eSZP/4zGCIBR0C4rs+6RM6U4eaf2ZuXqulBfUg2uRKIoKTX8ubk+6ZRZqYJSo3h9SBxgyuUrTehhOqmkMDo/oa9v7aUqAKw/uoaZKHlj+3p4L3EK0ZBpz8jjs/PXJc77Lk9ZKOUY+T0AW2Fz4syMaQOiETzQJBANF5q1lntAXN2TUWkzgir+H66HyyOpMu4meaSiktU8HWmKHa0tSB/v7LTfctnMjAbrcXywmb4ddixOgJLlAjEncCQQC6Enf3gfhEEgZTEz7WG9ev/M6hym4C+FhYKbDwk+PVLMVR7sBAtfPkiHVTVAqC082E1buZMzSKWHKAQzFL7o7zAkBye0VLOmLnnSWtXuYcktB+92qh46IhmEkCCA+py2zwDgEiy/3XSCh9Rc0ZXqNGD+0yQV2kpb3awc8NZR8bit9nAkBo4TgVnoCdfbtq4BIvBQqR++FMeJmBuxGwv+8n63QkGFQwVm6vCuAqFHBtQ5WZIGFbWk2fkKkwwaHogfcrYY/ZAkEAm5ibtJx/jZdPEF9VknswFTDJl9xjIfbwtUb6GDMc0KH7v+QTBW4GsHwt/gL+kGvLOLcEdLL5rau3IC7EQT0ZYg==";
    private static final String PUBLIC_KEY_STRING =  "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCYQYM3FwZuQNLK7xRbuBbAcviy1vl9LB//Ubz+NFSBjgrrGNPwqgOuWF1qskBOY0AnoAZpwHlWEryvtz1OGNX5q9boqrhOrGQebJfek9JGvjysz3+KCqAIup8C1Enp4+cUxYy7BRorjF6wqTAjyJn/SQVZPPUyVeN17Nw0jSqI9QIDAQAB";
    
    @Autowired
    private SslConfiguration sslConfiguration;
    
    @Value("${http.client.ssl.trust-store}")
    private Resource keyStore;

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
    
    KeyStore readKeyStore() throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException {
        KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());

        // get user password and file input stream
        char[] password = "password".toCharArray();

        java.io.FileInputStream fis = null;
        try {
            fis = new java.io.FileInputStream("E:/SQSImplementation/SQSImplementation/src/main/resources/tutorial.jks");
            ks.load(fis, password);
        } finally {
            if (fis != null) {
                fis.close();
            }
        }
        return ks;
    }
       
    public String getOAuthJWTToken() throws Exception {

    	
    	String jwtToken = new String();
    	String jwtTokenJson = new String();
    	
    	try {
    		
    		KeyStore keyStore = readKeyStore(); //your method to obtain KeyStore
    		SSLContext sslContext = SSLContext.getInstance("SSL");
    		TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
    		trustManagerFactory.init(keyStore);
    		KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
    		keyManagerFactory.init(keyStore, "password".toCharArray());
    		sslContext.init(keyManagerFactory.getKeyManagers(),trustManagerFactory.getTrustManagers(), new SecureRandom());
    	
    		OkHttpClient client = new OkHttpClient().newBuilder()
    				  .sslSocketFactory(sslContext.getSocketFactory(), (X509TrustManager) trustManagerFactory.getTrustManagers()[0])
    				  .build();
            
    		
			MediaType mediaType = MediaType.parse("application/x-www-form-urlencoded");
			RequestBody body = RequestBody.create(mediaType, "username=hendi&password=password&grant_type=password");
			Request request = new Request.Builder()
			  .url("https://localhost:8443/oauth/token")
			  .method("POST", body)
			  .addHeader("Content-Type", "application/x-www-form-urlencoded")
			  .addHeader("Accept", "application/json")
			  .addHeader("Authorization", "Basic aGVuZGktY2xpZW50OmhlbmRpLXNlY3JldA==")
			  .build();
			Response response = client.newCall(request).execute();
			jwtTokenJson = response.body().string();
			
			ObjectMapper mapper = new ObjectMapper();
			Map<String,Object> map = mapper.readValue(jwtTokenJson, Map.class);
			jwtToken = (String) map.get("access_token");
			
    	} catch (Exception e) {
    		System.out.println(e);
    	}
    	System.out.println(jwtToken);
    	return jwtToken;
    }


    public String getDecryptedMessage() {
        EncryptedService rsa = new EncryptedService();
        rsa.initFromStrings();
        String plainText = new String();

        try{
        	String access_token = this.getOAuthJWTToken();
        	ResponseEntity<String> response = 
        		      sslConfiguration.restTemplate().getForEntity("https://localhost:8443/users/allUsers?access_token={access_token}", String.class, access_token);
        	
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
            plainText = new String(bytePlainText);
            
            

        }catch (Exception ignored){
        	System.out.println(ignored);
        }
        return plainText;

    }
	
}
