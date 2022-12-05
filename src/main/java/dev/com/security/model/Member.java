package dev.com.security.model;

import dev.com.security.dto.MemberDto;
import jakarta.persistence.*;
import lombok.*;
import org.springframework.security.crypto.password.PasswordEncoder;

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

    private String name;

    @Column(unique = true)
    private String email;

    private String password;

    private String address;

//    @Enumerated(EnumType.STRING)
    private String roles;

    public Member(String name, String email, String password, String address, String roles) {
        this.name = name;
        this.email = email;
        this.password = password;
        this.address = address;
        this.roles = roles;
    }

    public static Member createMember(MemberDto memberDto, PasswordEncoder passwordEncoder){
        String password = passwordEncoder.encode(memberDto.getPassword());
        Member member = Member.builder()
                .email(memberDto.getEmail())
                .name(memberDto.getName())
                .password(password)
                .address(memberDto.getAddress())
                .roles("Admin")
                .build();

        return member;
    }

}