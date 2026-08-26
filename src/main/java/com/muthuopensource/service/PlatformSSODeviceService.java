package com.muthuopensource.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.muthuopensource.beans.DeviceRegistrationBean;
import com.muthuopensource.beans.JWKECKeyBean;
import com.muthuopensource.utils.PSSOUtils;
import com.muthuopensource.utils.ServerUtils;
import com.muthuopensource.utils.SystemConfiguration;


import java.io.File;
import java.nio.file.Path;


public class PlatformSSODeviceService {
    private static PlatformSSODeviceService instance = null;

    public static PlatformSSODeviceService getInstance(){
        if (instance==null){
            instance = new PlatformSSODeviceService();
        }
        return instance;
    }

    private PlatformSSODeviceService(){}

    public void addOrUpdateDeviceRegistrationKeys(DeviceRegistrationBean deviceRegistrationBean) throws Exception {
        addOrUpdateDeviceRegistrationKey(deviceRegistrationBean.getDeviceEncryptionKey(),
                deviceRegistrationBean.getSerialNumber(),
                PSSOUtils.FileNames.deviceEncryptionKey);
        addOrUpdateDeviceRegistrationKey(deviceRegistrationBean.getDeviceSigningKey(),
                deviceRegistrationBean.getSerialNumber(),
                PSSOUtils.FileNames.deviceSingingKey);
    }

    public String getDeviceSigningKey(String serialNumber){
        Path path = Path.of(SystemConfiguration.getConfiguration(ServerUtils.PropertyConstants.SERVER_FILES_STORAGE_DIRECTORY),serialNumber,PSSOUtils.FileNames.deviceSingingKey);
        File file = path.toAbsolutePath().toFile();
        return ServerUtils.readFileFromServer(file);
    }

    public String getDeviceEncryptionKey(String serialNumber){
        Path path = Path.of(SystemConfiguration.getConfiguration(ServerUtils.PropertyConstants.SERVER_FILES_STORAGE_DIRECTORY),serialNumber,PSSOUtils.FileNames.deviceEncryptionKey);
        File file = path.toAbsolutePath().toFile();
        return ServerUtils.readFileFromServer(file);
    }


    private void addOrUpdateDeviceRegistrationKey(JWKECKeyBean ecKeyBean,String serialNumber,String fileName) throws Exception {
        Path path = Path.of(SystemConfiguration.getConfiguration(ServerUtils.PropertyConstants.SERVER_FILES_STORAGE_DIRECTORY),serialNumber,fileName);
        File file = path.toAbsolutePath().toFile();
        ObjectMapper mapper = new ObjectMapper();
        String ecKeyString = mapper.writeValueAsString(ecKeyBean);
        ServerUtils.storeFileInServer(file,ecKeyString);
    }
}
