package dev.com.security.security;

import dev.com.security.model.Member;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;

public class SecurityMember implements UserDetails {

    private Member member;

    public SecurityMember(Member member) {
        this.member = member;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        Collection<GrantedAuthority> collection = new ArrayList<>();
        collection.add(new GrantedAuthority() {
            @Override
            public String getAuthority() {
                return member.getRoles();
            }
        });
        System.out.println("collection = " + collection);
        return collection;
    }

//        return Arrays.stream(member
//                .getRoles()
//                .split(","))
//                .map(SimpleGrantedAuthority::new)
//                .toList();
    @Override
    public String getPassword() {
        System.out.println("getPassword = " + member.getPassword());
        return member.getPassword();
    }

    @Override
    public String getUsername() {
        System.out.println("member.getUsername = " + member.getUsername());
        return member.getUsername();
    }

    @Override
    public boolean isAccountNonExpired() {
        return false;
    }

    @Override
    public boolean isAccountNonLocked() {
        return false;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return false;
    }

    @Override
    public boolean isEnabled() {
        return false;
    }
}
