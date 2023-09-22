package com.jwt.controllers;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/admin")
public class AdminController {
    
    @GetMapping
    @PreAuthorize("hasAuthority('admin:read')")
    public String get(){
        return "Hello fellow admin!";
    }

    @PostMapping
    @PreAuthorize("hasAuthority('admin:write')")
    public String post(){
        return "Thanks for the post";
    }

    @PutMapping
    @PreAuthorize("hasAuthority('admin:write')")
    public String put(){
        return "Thanks for the put";
    }

    @DeleteMapping
    @PreAuthorize("hasAuthority('admin:write')")
    public String delete(){
        return "Thanks for the delete";
    }
}
