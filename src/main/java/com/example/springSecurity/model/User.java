package com.example.springSecurity.model;

import jakarta.persistence.*;
import lombok.*;
import org.hibernate.annotations.CreationTimestamp;

import java.sql.Timestamp;

@Entity
@Data
@Table(name = "users")
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@AllArgsConstructor
public class User {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    @Column(unique = true)
    private String username;
    private String password;
    private String email;
    private String role = "ROLE_USER";
    private String provider;
    private String providerId;
    @Column(length = 400)
    private String refreshToken;
    @CreationTimestamp
    private Timestamp createDate;

    public void updateRefreshToken(String refreshToken){
        this.refreshToken = refreshToken;
    }

    @Builder
    public User(String username, String password, String email, String provider, String providerId){
        this.username = username;
        this.password = password;
        this.email = email;
        this.provider = provider;
        this.providerId = providerId;
    }
}
