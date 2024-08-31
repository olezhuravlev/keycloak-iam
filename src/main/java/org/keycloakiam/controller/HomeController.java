package org.keycloakiam.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class HomeController {

    @GetMapping("/")
    public ResponseEntity<String> home() {
        return ResponseEntity.ok("Hello!");
    }

    @GetMapping("/secured")
    public ResponseEntity<String> secured() {
        return ResponseEntity.ok("Hello secured!");
    }

    @GetMapping("/secured/admin")
    public ResponseEntity<String> securedAdmin() {
        return ResponseEntity.ok("Hello secured ADMIN!");
    }
}
