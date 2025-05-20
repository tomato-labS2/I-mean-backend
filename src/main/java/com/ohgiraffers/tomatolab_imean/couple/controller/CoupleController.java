package com.ohgiraffers.tomatolab_imean.couple.controller;


import com.ohgiraffers.tomatolab_imean.auth.model.AuthDetails;
import com.ohgiraffers.tomatolab_imean.couple.model.dto.CoupleRequestDTO;
import com.ohgiraffers.tomatolab_imean.couple.model.entity.Couple;
import com.ohgiraffers.tomatolab_imean.couple.service.CoupleService;
import com.ohgiraffers.tomatolab_imean.members.model.entity.Members;
import com.ohgiraffers.tomatolab_imean.members.service.MembersService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.crossstore.ChangeSetPersister.NotFoundException;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import java.util.Optional;

@Controller
@RequestMapping("/couple")
public class CoupleController {

    private final MembersService membersService;
    private final CoupleService coupleService;

    @Autowired
    public CoupleController(MembersService membersService, CoupleService coupleService) {
        this.membersService = membersService;
        this.coupleService = coupleService;
    }

    /**
     * 커플 등록 폼 페이지
     */
    @GetMapping("/register")
    public String showCoupleRegistrationForm(Authentication authentication, Model model) {
        if (!isAuthenticated(authentication)) {
            return "redirect:/auth/login";
        }

        try {
            AuthDetails authDetails = (AuthDetails) authentication.getPrincipal();
            Members currentMember = membersService.findByCode(authDetails.getMembersCode());
            
            // 이미 커플인 경우 커플 정보 페이지로 리다이렉트
            if (coupleService.isAlreadyInCouple(currentMember)) {
                model.addAttribute("message", "이미 커플 등록이 되어 있습니다.");
                return "redirect:/couple/info";
            }
            
            model.addAttribute("coupleRequestDTO", new CoupleRequestDTO());
            return "couple/register";
            
        } catch (Exception e) {
            model.addAttribute("message", "사용자 정보를 가져오는 중 오류가 발생했습니다.");
            return "error";
        }
    }

    /**
     * 커플 등록 처리
     */
    @PostMapping("/register")
    public String registerCouple(@ModelAttribute CoupleRequestDTO coupleRequestDTO,
                               Authentication authentication,
                               Model model,
                               RedirectAttributes redirectAttributes) {
        if (!isAuthenticated(authentication)) {
            return "redirect:/auth/login";
        }

        try {
            AuthDetails authDetails = (AuthDetails) authentication.getPrincipal();
            Members currentMember = membersService.findByCode(authDetails.getMembersCode());
            
            // 서비스를 통해 커플 등록 처리
            coupleService.registerCouple(currentMember, coupleRequestDTO.getTargetMemberCode());
            
            redirectAttributes.addFlashAttribute("message", "커플 등록이 완료되었습니다!");
            return "redirect:/couple/info";
            
        } catch (IllegalArgumentException e) {
            // 자신의 코드 입력 시
            model.addAttribute("message", e.getMessage());
            model.addAttribute("coupleRequestDTO", new CoupleRequestDTO());
            return "couple/register";
        } catch (IllegalStateException e) {
            // 이미 커플인 경우
            model.addAttribute("message", e.getMessage());
            return "couple/register";
        } catch (NotFoundException e) {
            // 존재하지 않는 멤버 코드
            model.addAttribute("message", "유효하지 않은 사용자 코드입니다.");
            model.addAttribute("coupleRequestDTO", new CoupleRequestDTO());
            return "couple/register";
        } catch (Exception e) {
            // 기타 예외
            model.addAttribute("message", "오류가 발생했습니다: " + e.getMessage());
            model.addAttribute("coupleRequestDTO", new CoupleRequestDTO());
            return "couple/register";
        }
    }
    
    /**
     * 커플 정보 보기
     */
    @GetMapping("/info")
    public String showCoupleInfo(Authentication authentication, Model model) {
        if (!isAuthenticated(authentication)) {
            return "redirect:/auth/login";
        }

        try {
            AuthDetails authDetails = (AuthDetails) authentication.getPrincipal();
            Members currentMember = membersService.findByCode(authDetails.getMembersCode());
            
            Optional<Couple> coupleOptional = coupleService.findCoupleByMember(currentMember);
            
            if (coupleOptional.isPresent()) {
                Couple couple = coupleOptional.get();
                model.addAttribute("couple", couple);
                
                // 커플 상대방 정보 추가
                Members partner = coupleService.getPartner(couple, currentMember);
                model.addAttribute("partner", partner);
                
                return "couple/info";
            } else {
                model.addAttribute("message", "아직 커플 관계가 존재하지 않습니다.");
                return "couple/no-couple";
            }
        } catch (Exception e) {
            model.addAttribute("message", "오류가 발생했습니다: " + e.getMessage());
            return "couple/error";
        }
    }
    
    /**
     * 인증 여부 확인 헬퍼 메서드
     */
    private boolean isAuthenticated(Authentication authentication) {
        return authentication != null && 
               authentication.isAuthenticated() && 
               authentication.getPrincipal() instanceof AuthDetails;
    }
}