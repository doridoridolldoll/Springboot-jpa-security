package dev.com.security.repository;

import dev.com.security.model.Member;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import java.util.Optional;

public interface MemberRepository extends JpaRepository<Member,Long> {

//    Optional<Member> findByEmail(String email);
    @Query("select m from Member m where m.email =:email ")
    Member findByEmail(String email);

    Member findByUsername(String username);
}