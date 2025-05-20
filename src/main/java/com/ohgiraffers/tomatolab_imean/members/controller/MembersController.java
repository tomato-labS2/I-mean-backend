package com.ohgiraffers.tomatolab_imean.members.controller;


import com.ohgiraffers.tomatolab_imean.auth.model.AuthDetails;
import com.ohgiraffers.tomatolab_imean.members.model.dto.MembersDTO;
import com.ohgiraffers.tomatolab_imean.members.model.dto.SinupDTO;
import com.ohgiraffers.tomatolab_imean.members.service.MembersService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import java.util.Random;

@Controller
@RequestMapping("/members")
public class MembersController {
    private MembersService membersService;
    private PasswordEncoder passwordEncoder;

    @Autowired
    public MembersController(MembersService membersService, PasswordEncoder passwordEncoder) {
        this.membersService = membersService;
        this.passwordEncoder = passwordEncoder;
    }

    @GetMapping("/signup")
    public String showSignupForm(Model model) {
        model.addAttribute("signupMembersDTO", new SinupDTO());
        return "members/register";
    }

    @PostMapping("/signup")
    public String registerMembers(@ModelAttribute SinupDTO sinupDTO, Model model, RedirectAttributes redirectAttributes) {
        // 랜덤 membersCode 생성
        String randomMembersCode = generateRandomMembersCode();
        sinupDTO.setMembersCode(randomMembersCode);

        Long result = membersService.registerMembers(sinupDTO);
        String message = null;

        if (result == -1) {
            // 중복된 membersCode 발생 시 재시도
            for (int i = 0; i < 5; i++) { // 최대 5번 재시도
                randomMembersCode = generateRandomMembersCode();
                sinupDTO.setMembersCode(randomMembersCode);
                result = membersService.registerMembers(sinupDTO);
                if (result > 0) break; // 성공하면 반복 중단
                if (result != -1) break; // membersCode 중복이 아닌 다른 오류면 중단
            }
            
            // 여전히 실패하면 에러 메시지 표시
            if (result == -1) {
                message = "중복된 회원코드가 생성되었습니다. 다시 시도해 주세요.";
                model.addAttribute("message", message);
                return "members/register";
            }
        }

        if (result == -2) {
            message = "중복된 이메일이 존재합니다.";
            model.addAttribute("message", message);
            return "members/register";
        } else if (result == -3) {
            message = "중복된 전화번호가 존재합니다.";
            model.addAttribute("message", message);
            return "members/register";
        } else if (result == 0) {
            message = "서버에 오류가 발생하였습니다.";
            model.addAttribute("message", message);
            return "members/register";
        } else {
            message = "회원가입이 완료되었습니다.";
            redirectAttributes.addFlashAttribute("message", message);
            return "redirect:/auth/login";
        }
    }

    // 랜덤 membersCode 생성 메소드
    private String generateRandomMembersCode() {
        // 랜덤 알파벳 대문자와 숫자 조합으로 10자리 코드 생성
        StringBuilder sb = new StringBuilder();
        String characters = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
        Random random = new Random();
        
        for (int i = 0; i < 10; i++) {
            int index = random.nextInt(characters.length());
            sb.append(characters.charAt(index));
        }
        
        return sb.toString();
    }

    @GetMapping("/profile")
    public String showMembersProfile(Authentication authentication, Model model) {
        if (authentication != null && authentication.isAuthenticated()) {
            if (authentication.getPrincipal() instanceof AuthDetails) {
                AuthDetails authDetails = (AuthDetails) authentication.getPrincipal();
                MembersDTO membersDTO = membersService.findById(authDetails.getMembersId());

                model.addAttribute("members", membersDTO);
                return "members/detail";
            }
        }

        return "redirect:/";
    }

    @GetMapping("/password-verify")
    public String showPasswordVerificationForm(Authentication authentication,
                                               Model model,
                                               RedirectAttributes redirectAttributes) {
        // 로그인 상태 확인
        if (authentication != null && authentication.isAuthenticated()) {
            if (authentication.getPrincipal() instanceof AuthDetails) {
                AuthDetails authDetails = (AuthDetails) authentication.getPrincipal();
//                String status = authDetails.getMembersStatus();

                return "members/verify";
            }
        }

        return "redirect:/";
    }

    @PostMapping("/password-verify")
    public String verifyPassword(Authentication authentication,
                                 @RequestParam String verifyPassword,
                                 Model model,
                                 RedirectAttributes redirectAttributes) {
        if (authentication != null && authentication.isAuthenticated()) {
            if (authentication.getPrincipal() instanceof AuthDetails) {
                AuthDetails authDetails = (AuthDetails) authentication.getPrincipal();

                String encodedPassword = authDetails.getPassword();

                if (!passwordEncoder.matches(verifyPassword, encodedPassword)) {
                    model.addAttribute("message", "비밀번호가 일치하지 않습니다.");
                    return "members/verify";
                }

                MembersDTO membersDTO = membersService.findById(authDetails.getMembersId());
                model.addAttribute("members", membersDTO);
                return "members/edit";
            }
        }

        return "redirect:/";
    }

    @PatchMapping("/profile")
    public String updateMembersProfile(Authentication authentication, @ModelAttribute MembersDTO updateMembers,
                                    RedirectAttributes redirectAttributes) {
        String message = null;

        if (authentication != null && authentication.isAuthenticated()) {
            if (authentication.getPrincipal() instanceof AuthDetails) {
                AuthDetails authDetails = (AuthDetails) authentication.getPrincipal();
                Long membersId = authDetails.getMembersId();

                boolean result = membersService.updateProfile(membersId, updateMembers);

                if (!result) {
                    message = "회원 정보를 찾을 수 없습니다.";
                    redirectAttributes.addFlashAttribute("message", message);
                    return "redirect:/members/update";
                }

                // 비밀번호가 수정된 경우
                if (updateMembers.getMembersPass() != null && !updateMembers.getMembersPass().trim().isEmpty()) {
                    // 현재 HTTP 요청 및 세션 가져오기
                    HttpServletRequest request = ((ServletRequestAttributes) RequestContextHolder.getRequestAttributes()).getRequest();
                    HttpSession session = request.getSession(false);

                    // 세션 무효화
                    if (session != null) {
                        session.invalidate();
                    }

                    // 보안 컨텍스트 클리어
                    SecurityContextHolder.clearContext();

                    redirectAttributes.addFlashAttribute("message",
                            "비밀번호가 성공적으로 변경되었습니다. 새 비밀번호로 다시 로그인해주세요.");
                    return "redirect:/";
                }

                // 비밀번호 외 정보만 수정된 경우
                message = "회원 정보가 업데이트 되었습니다.";
                redirectAttributes.addFlashAttribute("message", message);
                return "redirect:/members/profile";
            }
        }

        return "redirect:/";
    }
}