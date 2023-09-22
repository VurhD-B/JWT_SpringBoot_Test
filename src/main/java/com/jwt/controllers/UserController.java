package com.jwt.controllers;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/user")
public class UserController {
    
    @GetMapping
    @PreAuthorize("hasAuthority('user:read')")
    public String get() {
        return "Hello User";
    }

    @PostMapping
    @PreAuthorize("hasAuthority('user:write')")
    public String post() {
        return "Thanks for the post User";
    }

    @PutMapping
    @PreAuthorize("hasAuthority('user:write')")
    public String put() {
        return "Thanks for the put User";
    }

    @DeleteMapping
    @PreAuthorize("hasAuthority('user:write')")
    public String delete() {
        return "Thanks for the delete User";
    }
}
