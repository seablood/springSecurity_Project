package com.example.springSecurity.repository;

import com.example.springSecurity.model.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface UserRepository extends JpaRepository<User, Long> {
    User findByUsername(String username);
    User findByProviderAndProviderId(String provider, String providerId);
}
