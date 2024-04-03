package com.example.loginlogout.user;

import jakarta.persistence.*;
import lombok.*;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.stream.Collectors;

@Builder
@Getter
@Entity
@Table(name = "user")
public class User {
    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    public Long id;
    public String password;
    public String email;
    public String birth;
    public String nickname;
    @ElementCollection(fetch = FetchType.EAGER)
    @Builder.Default
    public List<String> roles = new ArrayList<>();

    public User() {
    }

    public User(Long id, String password, String email, String birth, String nickname, List<String> roles) {
        this.id = id;
        this.password = password;
        this.email = email;
        this.birth = birth;
        this.nickname = nickname;
        this.roles = roles;
    }
    /*

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return roles.stream()
                .map(SimpleGrantedAuthority::new)
                .collect(Collectors.toList());
    }
    @Override
    public String getPassword() {
        return password;
    }

    @Override
    public String getUsername() {
        return email;
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }*/
}