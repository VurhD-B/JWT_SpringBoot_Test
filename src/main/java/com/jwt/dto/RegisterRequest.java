package com.jwt.dto;


import java.util.Date;

import com.jwt.models.Role;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class RegisterRequest {
    private String email;
    private String password;
    private String phoneNumber;
    private Date dateOfBirth;
    private Role role;
}
