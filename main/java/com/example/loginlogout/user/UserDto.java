package com.example.loginlogout.user;

import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;

@Getter
@Setter
@NoArgsConstructor
public class UserDto implements Serializable {
    private String email;
    private String password;
    private String birth;
    private String nickname;
    private List<String> roles = new ArrayList<>();

    public User toEntity() {
        return User.builder()
                .email(email)
                .password(password)
                .birth(birth)
                .nickname(nickname)
                .roles(roles)
                .build();
    }

    public UserDto(User user) {
        this.email = user.getEmail();
        this.password = user.getPassword();
        this.birth = user.getBirth();
        this.nickname = user.getNickname();
        this.roles = user.getRoles();
    }
}
