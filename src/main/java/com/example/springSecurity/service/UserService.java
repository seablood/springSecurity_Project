package com.example.springSecurity.service;

import com.example.springSecurity.dto.CreateUserDTO;
import com.example.springSecurity.dto.ResponseUserDTO;
import com.example.springSecurity.model.User;
import com.example.springSecurity.repository.UserRepository;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class UserService {
    private final UserRepository userRepository;
    private final BCryptPasswordEncoder bCryptPasswordEncoder;
    @Value("${jwt.secretKey}")
    private String secretKey;

    @Transactional
    public User save(CreateUserDTO dto){
        dto.setPassword(bCryptPasswordEncoder.encode(dto.getPassword()));
        User user = CreateUserDTO.toEntity(dto);
        System.out.println(secretKey);
        return userRepository.save(user);
    }

    public ResponseUserDTO findById(Long id){
        User user = userRepository.findById(id)
                .orElseThrow(() -> new IllegalArgumentException("유저를 찾지 못했습니다."));

        return ResponseUserDTO.toDto(user);
    }
}
