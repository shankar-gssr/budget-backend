package com.shank.budget.auth;

import com.shank.budget.config.JwtUtils;
import com.shank.budget.login.LoginEntity;
import com.shank.budget.login.LoginEntityRepository;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.util.Optional;

@RestController
@RequestMapping("/auth")
public class AuthenticationController {

    @Autowired
    HttpServletRequest request;

    @Autowired
    PasswordEncoder passwordEncoder;

    @Autowired
    JwtUtils jwtUtils;

    @Autowired
    LoginEntityRepository loginRepository;

    @PostMapping("/authenticate")
    public String authenticate(@RequestBody LoginRequest loginRequest) {
        String userName = loginRequest.getUserName();
        String password = loginRequest.getPassword();
        LoginEntity user = loginRepository.findByUsername(userName);
        if(user == null) {
            throw new RuntimeException("Wrong Username/Password, Please check details!");
        }
        if(matches(password, user.getPassword())) {
            return jwtUtils.generateAccessToken(user);
        }
        throw new RuntimeException("Wrong Username/Password, Please check details!");
    }

    public String hashPassword(String rawPassword) {
        return passwordEncoder.encode(rawPassword);
    }

    public boolean matches(String rawPassword, String hashedPassword) {
        return passwordEncoder.matches(rawPassword, hashedPassword);
    }
}
