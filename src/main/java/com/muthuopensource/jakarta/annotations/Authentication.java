package com.muthuopensource.jakarta.annotations;

import com.muthuopensource.utils.AuthenitcationType;
import jakarta.ws.rs.NameBinding;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

@Retention(RetentionPolicy.RUNTIME)
@Target({ElementType.TYPE,ElementType.METHOD})
@NameBinding
public @interface Authentication {
    AuthenitcationType value() default AuthenitcationType.NONE;
}
