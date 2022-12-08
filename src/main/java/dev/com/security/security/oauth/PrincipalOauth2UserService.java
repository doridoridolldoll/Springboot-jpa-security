package dev.com.security.security.oauth;

import dev.com.security.model.Member;
import dev.com.security.repository.MemberRepository;
import dev.com.security.security.auth.PrincipalDetails;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

@Configuration
public class PrincipalOauth2UserService extends DefaultOAuth2UserService {

    @Autowired
    private MemberRepository memberRepository;

    //구글로 부터 받은 userRequest 데이터에 대한 후처리되는 함수
    //함수 종료시 @AuthenticationPrincipal 어노테이션이 만들어진다.
    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        //registrationId로 어떤 OAuth로 로그인하는지 확인 가능
        System.out.println("getClientRegistration = " + userRequest.getClientRegistration());
        System.out.println("getAccessToken = " + userRequest.getAccessToken().getTokenValue());

        OAuth2User oAuth2User = super.loadUser(userRequest);
        //구글로그인 버튼 클릭 -> 구글 로그인 창 -> 로그인 완료 -> code return(oauth-client library) -> 액세스 토큰 요청
        //userRequest 정보 -> loadUser 함수 호출 -> 구글로부터 회원프로필 받아옴
        System.out.println("getAttributes = " + oAuth2User.getAttributes());

        String provider = userRequest.getClientRegistration().getClientId(); //google
        String providerId = oAuth2User.getAttribute("sub");
        String username = provider + "_" + providerId;
        String email = oAuth2User.getAttribute("email");
        String role = "ROLE_USER";

        Member userEntity = memberRepository.findByUsername(username);

        if (userEntity == null) {
            System.out.println("구글 로그인이 최초입니다.");
            userEntity = Member.builder()
                    .username(username)
                    .email(email)
                    .roles(role)
                    .provider(provider)
                    .providerId(providerId)
                    .build();
            memberRepository.save(userEntity);
        } else {
            System.out.println("구글 로그인을 미이 한적이 있습니다.");
        }

        return new PrincipalDetails(userEntity, oAuth2User.getAttributes());
    }
}
