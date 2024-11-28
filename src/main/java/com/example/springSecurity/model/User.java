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
    private String username;
    private String password;
    private String email;
    private String role = "ROLE_USER";
    @CreationTimestamp
    private Timestamp createDate;

    @Builder
    public User(String username, String password, String email){
        this.username = username;
        this.password = password;
        this.email = email;
    }
}
