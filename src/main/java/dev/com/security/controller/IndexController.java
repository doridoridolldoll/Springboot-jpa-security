package dev.com.security.controller;

import dev.com.security.dto.MemberDto;
import dev.com.security.model.Member;
import dev.com.security.service.MemberService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.ResponseBody;

@Controller
@RequiredArgsConstructor
@Slf4j
public class IndexController {

    private final MemberService memberService;
    private final PasswordEncoder passwordEncoder;

//    @GetMapping({"", "/"})
//    public String index() {
//        return "index";
//    }

    @GetMapping("/user")
    public @ResponseBody String user() {
        return "user";
    }

    @GetMapping("/admin")
    public @ResponseBody String admin() {
        return "admin";
    }

    @GetMapping("/manager")
    public String manager() {
        return "manager";
    }

    @GetMapping("/loginForm")
    public String loginForm(Model model) {
        model.addAttribute("memberDto", new MemberDto());
        return "loginForm";
    }

    @GetMapping("/members/new")
    public String memberForm(Model model){
        model.addAttribute("memberDto", new MemberDto());
        return "members/joinForm";
    }

    @PostMapping("/members/new")
    public String newMember(MemberDto memberDto){
        log.info("memberDto = {}", memberDto);
        Member entity = memberService.dtoToEntity(memberDto);
        memberService.saveMember(entity);
        return "redirect:/loginForm";
    }
}
