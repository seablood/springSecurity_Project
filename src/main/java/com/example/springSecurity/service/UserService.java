package com.example.springSecurity.service;

import com.example.springSecurity.dto.CreateUserDTO;
import com.example.springSecurity.model.User;
import com.example.springSecurity.repository.UserRepository;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class UserService {
    private final UserRepository userRepository;
    private final BCryptPasswordEncoder bCryptPasswordEncoder;

    @Transactional
    public User save(CreateUserDTO dto){
        dto.setPassword(bCryptPasswordEncoder.encode(dto.getPassword()));
        User user = CreateUserDTO.toEntity(dto);
        return userRepository.save(user);
    }
}
