package com.cwa.springboot_app.controller;


import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/auth")
public class UserController {

    @GetMapping("/users")
    public ResponseEntity<String> helloSecure() {
        return ResponseEntity.ok("Accès sécurisé autorisé !");
    }
}