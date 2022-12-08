package dev.com.security.model;

import dev.com.security.dto.MemberDto;
import jakarta.persistence.*;
import lombok.*;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

@Entity
@Table(name = "member")
@Getter
@Builder
@NoArgsConstructor
@AllArgsConstructor
@ToString
public class Member {

    @Id
    @Column(name = "member_id")
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    private String username;
    @Column(unique = true)
    private String email;
    private String password;
    private String address;

//    @Enumerated(EnumType.STRING)
    private String roles;
    private String provider;
    private String providerId;

    public Member(String username, String email, String password, String address, String roles) {
        this.username = username;
        this.email = email;
        this.password = password;
        this.address = address;
        this.roles = roles;
    }

    public Member(String username, String email, String password, String address, String roles,
                  String provider, String providerId) {
        this.username = username;
        this.email = email;
        this.password = password;
        this.address = address;
        this.roles = roles;
        this.provider = provider;
        this.providerId = providerId;
    }

    public List<String> getRolesList() {
        if (this.roles.length() > 0) {
            return Arrays.asList(this.roles.split("m"));
        }
        return new ArrayList<>();
    }
}