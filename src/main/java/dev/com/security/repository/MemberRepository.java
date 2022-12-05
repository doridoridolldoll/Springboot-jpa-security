package dev.com.security.repository;

import dev.com.security.model.Member;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface MemberRepository extends JpaRepository<Member,Long> {

    Optional<Member> findByEmail(String email);

//    Member findByEmail(String email);
}