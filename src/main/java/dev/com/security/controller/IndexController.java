package dev.com.security.controller;

import dev.com.security.dto.MemberDto;
import dev.com.security.model.Member;
import dev.com.security.security.auth.PrincipalDetails;
import dev.com.security.service.MemberService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.access.annotation.Secured;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.ResponseBody;

import java.util.Collection;
import java.util.Collections;

@Controller
@RequiredArgsConstructor
@Slf4j
public class IndexController {

    private final MemberService memberService;

    @GetMapping("/test/login")
    public @ResponseBody String testLogin(Authentication authentication,
                                          @AuthenticationPrincipal PrincipalDetails userDetails) { //DI(의존성 주입)
        System.out.println("/test/login ========================");
        PrincipalDetails principalDetails = (PrincipalDetails) authentication.getPrincipal();
        System.out.println("authentication = " + principalDetails.getMember());
        System.out.println("userDetails = " + userDetails.getMember());
        return "세션 정보 확인";
    }

    @GetMapping("/test/oauth/login")
    public @ResponseBody String testOAuthLogin(Authentication authentication,
                                               @AuthenticationPrincipal OAuth2User user) { //DI(의존성 주입)
        System.out.println("/test/oauth/login ========================");
        OAuth2User oAuth2User = (OAuth2User) authentication.getPrincipal();
        System.out.println("authentication = " + oAuth2User.getAttributes());
        System.out.println("user = " + user.getAttributes());
        return "OAuth 세션 정보 확인";
    }

    @GetMapping("/api/user")
    public @ResponseBody String user(@AuthenticationPrincipal PrincipalDetails principalDetails) {
        System.out.println("securityMember = " + principalDetails.getMember());
        return "user";
    }

    @GetMapping("/api/admin")
    public @ResponseBody String admin() {
        return "admin";
    }

    @GetMapping("/api/manager")
    public @ResponseBody String manager() {
        return "manager";
    }

    @GetMapping("/loginForm")
    public String loginForm(Model model) {
        model.addAttribute("memberDto", new MemberDto());
        return "loginForm";
    }

    @GetMapping("/members/new")
    public String memberForm(Model model) {
        model.addAttribute("memberDto", new MemberDto());
        return "members/joinForm";
    }

    @PostMapping("/members/new")
    public String newMember(Member member) {
//        log.info("memberDto = {}", memberDto);
//        memberDto.setRoles("ROLE_MANAGER");
//        Member entity = memberService.dtoToEntity(memberDto);
        Member entity = Member.builder()
                .username(member.getUsername())
                .password(member.getPassword())
                .roles(Collections.singleton(new SimpleGrantedAuthority("ROLE_MANAGER")).toString())
                .build();
        memberService.saveMember(entity);
        return "redirect:/loginForm";
    }

    @GetMapping("/info")
    @Secured("ROLE_ADMIN")
    public @ResponseBody String info() {
        return "개인정보";
    }

    @GetMapping("/data")
    @PreAuthorize("hasRole('ROLE_MANAGER') or hasRole('ROLE_ADMIN')")
    public @ResponseBody String data() {
        return "데이터";
    }

    @GetMapping("/home")
    public @ResponseBody String home() {
        return "<h1>home</h1>";
    }

    @PostMapping("/token")
    public @ResponseBody String token() {
        return "<h1>token</h1>";
    }
}
