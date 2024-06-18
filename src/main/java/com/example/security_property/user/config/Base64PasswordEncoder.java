//package com.example.security_property.user.config;
//
//import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
//import org.springframework.security.crypto.password.PasswordEncoder;
//
//import java.nio.charset.StandardCharsets;
//import java.util.Base64;
//
//public class Base64PasswordEncoder implements PasswordEncoder {
//
//    private final BCryptPasswordEncoder bCryptPasswordEncoder = new BCryptPasswordEncoder();
//
//    @Override
//    public String encode(CharSequence rawPassword) {
//        // First, encode the raw password using Base64
//        String base64EncodedPassword = Base64.getEncoder().encodeToString(rawPassword.toString().getBytes(StandardCharsets.UTF_8));
//        // Then, hash the Base64-encoded password using BCrypt
//        return bCryptPasswordEncoder.encode(base64EncodedPassword);
//    }
//
//    @Override
//    public boolean matches(CharSequence rawPassword, String encodedPassword) {
//        // First, encode the raw password using Base64
//        String base64EncodedPassword = Base64.getEncoder().encodeToString(rawPassword.toString().getBytes(StandardCharsets.UTF_8));
//        // Then, check if the BCrypt hash of the Base64-encoded password matches the stored hash
//        return bCryptPasswordEncoder.matches(base64EncodedPassword, encodedPassword);
//    }
//}
