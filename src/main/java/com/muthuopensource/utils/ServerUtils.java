package com.muthuopensource.utils;

import com.muthuopensource.service.OIDCService;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.oauth2.sdk.GeneralException;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.Security;
import java.util.UUID;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

public class ServerUtils {

    public static ScheduledExecutorService executor = Executors.newSingleThreadScheduledExecutor();

    private static Logger logger = LoggerFactory.getLogger(ServerUtils.class);

    public class PropertyConstants{
        public static String PSSO_AUTH_CODE_GRANT_OIDC_PROVIDER_URL = "PSSO_AUTH_CODE_GRANT_OIDC_PROVIDER_URL";
        public static String PSSO_AUTH_CODE_GRANT_OIDC_CLIENT_ID = "PSSO_AUTH_CODE_GRANT_OIDC_CLIENT_ID";
        public static String PSSO_AUTH_CODE_GRANT_OIDC_CLIENT_SECRET = "PSSO_AUTH_CODE_GRANT_OIDC_CLIENT_SECRET";
        public static String PSSO_SERVER_KEY_PROTECTION_PASSWORD = "PSSO_SERVER_KEY_PROTECTION_PASSWORD";
        public static String PSSO_ROPG_OIDC_PROVIDER_URL = "PSSO_ROPG_OIDC_PROVIDER_URL";
        public static String PSSO_ROPG_CLIENT_ID = "PSSO_ROPG_CLIENT_ID";
        public static String PSSO_ROPG_CLIENT_SECRET = "PSSO_ROPG_CLIENT_SECRET";
        public static String PSSO_HMAC_SECRET_KEY = "PSSO_HMAC_SECRET_KEY";
        public static String SERVER_FILES_STORAGE_DIRECTORY = "SERVER_FILES_STORAGE_DIRECTORY";
    }

    /**
     * Util Used to Store the File in Server in the mentioned File Path
     * @param file File Path
     * @param fileContents String representing the contents to be stored in File Path
     * @throws Exception
     */
    public static void storeFileInServer(File file, String fileContents) throws Exception {
        logger.info("ServerUtils : Going to {} File, File Path : {}",file.exists() ? "update":"add",file.getAbsolutePath());
        Files.createDirectories(file.toPath().getParent());
        try(BufferedWriter bufferedWriter = new BufferedWriter(new FileWriter(file))){
            bufferedWriter.write(fileContents);
        }catch (IOException e){
            logger.error("ServerUtils : Exception Occured while Writing File to Server, File Path : {}",file.getAbsolutePath());
            logger.error("ServerUtils : Exception Occured while Writing File to Server",e);
            throw e;
        }
    }

    /**
     * Util Used to read the File Contents in Server Stored in mentioned File Path
     * @param file File Path
     * @return
     * @throws Exception
     */
    public static String readFileFromServer(File file) {
        logger.atDebug().log("ServerUtils : File {} at File Path : {}",file.exists() ? "exists" : "doesn't exists",file.getAbsolutePath());
        logger.info("ServerUtils : Going to Read File from File Path : {}",file.getAbsolutePath());
        CharArrayWriter charArrayWriter = new CharArrayWriter();
        try(BufferedWriter bufferedWriter = new BufferedWriter(charArrayWriter);
            BufferedReader bufferedReader = new BufferedReader(new FileReader(file))){
            bufferedReader.transferTo(bufferedWriter);
        } catch (IOException e){
            logger.error("ServerUtils : Exception Occured while Reading File from Server, File Path : {}",file.getAbsolutePath());
            logger.error("ServerUtils : Exception Occured while Reading File from Server",e);
        }
        return charArrayWriter.toString();
    }

    /**
     * Util Used to Create a ECKey which is meant to be securely used by Server for Singing, Encryption operations onbehalf of server
     * The ECKey is Stores securely as JWE using PSSO_SERVER_KEY_PROTECTION_PASSWORD
     *
     * Eg : ( 1. Used for Signing ID Token in Login Request );
     * @return ECKey
     */
    public static ECKey generateServerSigningKey(){
        try {
            Path serverSigningKeyPath = Path.of(SystemConfiguration.getConfiguration(ServerUtils.PropertyConstants.SERVER_FILES_STORAGE_DIRECTORY),"serverSigningKey.jwe");
            File file = serverSigningKeyPath.toFile();

            if(Files.exists(file.toPath())){
                return getServerSigningKey();
            }
            ECKey ecKey = new ECKeyGenerator(Curve.P_256)
                    .keyID(UUID.randomUUID().toString())
                    .generate();
            Payload payload = new Payload(ecKey.toJSONString());
            String serverSigningKeySecret = SystemConfiguration.getConfiguration(PropertyConstants.PSSO_SERVER_KEY_PROTECTION_PASSWORD);
            String fileContentsToBeStored = CryptoUtil.generateJWE("JOSE",serverSigningKeySecret, payload, 16,100000)
                            .serialize();
            logger.atDebug().log("Generating Server Signing Key at Path : {}",serverSigningKeyPath.toAbsolutePath());
            storeFileInServer(file, fileContentsToBeStored);
            return ecKey;
        } catch (Exception e) {
            logger.error("ServerUtils : Error Occured during Server Signing Key Generation",e);
            Runtime.getRuntime().exit(1);
        }
        return null;
    }

     private static ECKey getServerSigningKey() throws Exception {
        Path serverSigningKeyPath = Path.of(SystemConfiguration.getConfiguration(ServerUtils.PropertyConstants.SERVER_FILES_STORAGE_DIRECTORY),"serverSigningKey.jwe");
        logger.atDebug().log("Getting Server Signing Key from Path : {}",serverSigningKeyPath.toAbsolutePath());
        File file = serverSigningKeyPath.toFile();
        String jweContents = readFileFromServer(file);
        String serverSigningKeySecret = SystemConfiguration.getConfiguration(PropertyConstants.PSSO_SERVER_KEY_PROTECTION_PASSWORD);
        Payload payload = CryptoUtil.decryptJWE(serverSigningKeySecret, JWEObject.parse(jweContents))
                .getPayload();
        return ECKey.parse(payload.toString());
    }

    /**
     * Used to Sync OIDCMetaData Daily inorder to sync changes in openid discovery cpnfiguration.
     */
    public static void registerOIDCMetaDataSyncTask(){
        executor.scheduleWithFixedDelay(
                ()->{
                    try {
                        OIDCService.OIDCMetaData.syncOIDCMetaData();
                    } catch (GeneralException e) {
                        throw new RuntimeException(e);
                    } catch (IOException e) {
                        throw new RuntimeException(e);
                    }
                },
                0,
                24,
                TimeUnit.HOURS
        );
    }

    public static void registerBC(){
        Security.addProvider(new BouncyCastleProvider());
    }
}

