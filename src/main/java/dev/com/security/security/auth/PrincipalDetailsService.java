package dev.com.security.security.auth;

import dev.com.security.model.Member;
import dev.com.security.repository.MemberRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

// 시큐리티 설정에서 loginProcessingUrl("/members/login")
// login 요청이 오면 자동으로 UserDetailsService 타입으로 IoC되어 있는 loadUserByUsername 함수가 실행
@Service
@RequiredArgsConstructor
public class PrincipalDetailsService implements UserDetailsService {

    private final MemberRepository memberRepository;

    //시큐리티 session(내부 Authentication(내부 UserDetails))
    //함수 종료시 @AuthenticationPrincipal 어노테이션이 만들어진다.
    @Override
    @Transactional
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        System.out.println("username = " + username);
        Member userEntity = memberRepository.findByUsername(username);
        System.out.println("userEntity = " + userEntity);
//        if (userEntity != null) {
//            return new PrincipalDetails(userEntity);
//        }
        return new PrincipalDetails(userEntity);
//        return memberRepository
//                .findByEmail(email)
//                .map(SecurityMember::new)
//                .orElseThrow(() -> new UsernameNotFoundException("Email not found: " + email));
    }
}
