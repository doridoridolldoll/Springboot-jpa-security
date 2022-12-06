package dev.com.security.service;

import dev.com.security.dto.MemberDto;
import dev.com.security.model.Member;
import dev.com.security.repository.MemberRepository;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Optional;
import java.util.stream.Stream;

@Service
@Transactional
@RequiredArgsConstructor
public class MemberService {

    private final MemberRepository memberRepository;
    private final PasswordEncoder passwordEncoder;
    private final BCryptPasswordEncoder bCryptPasswordEncoder;

    public Member saveMember(Member member){
//        validateDuplicateMember(member.getEmail());
        return memberRepository.save(member);
    }

//    private void validateDuplicateMember(MemberDto memberDto){
//        Member findMember = memberRepository.findByEmail(memberDto.getEmail());
////        Stream<String> email = findMember.stream().map(i -> i.getEmail());
//        if(findMember.getEmail().equals(memberDto.getEmail())){
//            throw new IllegalStateException("이미 가입된 회원 입니다.");
//        }
//    }
    public Member dtoToEntity(MemberDto dto) {
            String password = bCryptPasswordEncoder.encode(dto.getPassword());
            Member member = Member.builder()
                    .username(dto.getUsername())
                    .email(dto.getEmail())
                    .password(password)
                    .address(dto.getAddress())
                    .roles(dto.getRoles())
                    .build();
            return member;
    }
}