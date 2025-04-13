package com.cwa.springboot_app.repository;

import com.cwa.springboot_app.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;

public interface UserRepository extends JpaRepository<User, Long> {
    User findByUsername(String username);
    //User findByEmail(String email);
}
