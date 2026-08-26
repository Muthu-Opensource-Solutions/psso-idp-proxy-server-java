package com.muthuopensource.beans;


import lombok.Getter;
import lombok.Setter;
import lombok.ToString;

@Getter
@Setter
@ToString
public class DeviceRegistrationBean {
    private JWKECKeyBean deviceEncryptionKey;
    private JWKECKeyBean deviceSigningKey;
    private String serialNumber;
}
