package com.shank.budget.login;

import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface LoginEntityRepository extends JpaRepository<LoginEntity, Long> {
    LoginEntity findByUsername(String username);
}