package com.shank.budget.auth;

import lombok.Data;

@Data
public class LoginRequest {
    String userName;
    String password;
}
