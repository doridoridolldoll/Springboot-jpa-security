package dev.com.security.dao;

import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Repository;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

@Repository
public class UserDao {

    private final static List<UserDetails> APPLICATION_USERS = Arrays.asList(
            new User(
                    "song",
                    "1234",
                    Collections.singleton(new SimpleGrantedAuthority("ROLE_MANAGER"))
            ),
            new User(
                    "jinu",
                    "1234",
                    Collections.singleton(new SimpleGrantedAuthority("ROLE_ADMIN"))
            )
    );

    public UserDetails loadUserByUsername(String username) {
        return APPLICATION_USERS
                .stream()
                .filter(u -> u.getUsername().equals(username))
                .findFirst()
                .orElseThrow(() -> new UsernameNotFoundException("No user was found"));
    }
}
