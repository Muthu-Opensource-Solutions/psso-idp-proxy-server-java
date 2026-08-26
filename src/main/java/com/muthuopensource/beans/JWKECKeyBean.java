package com.muthuopensource.beans;


import lombok.Getter;
import lombok.Setter;
import lombok.ToString;

@Getter
@Setter
@ToString
public class JWKECKeyBean {

    private String kid;// We should SHA-256 Hash the ANSI 5.92 format of the key from macOS Extension and use it as kid
    private String kty;
    private String crv;
    private String x;
    private String y;
}
