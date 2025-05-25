package com.ohgiraffers.tomatolab_imean.couple.controller;

import com.ohgiraffers.tomatolab_imean.auth.model.AuthDetails;
import com.ohgiraffers.tomatolab_imean.common.dto.response.ApiResponseDTO;
import com.ohgiraffers.tomatolab_imean.common.exception.UnauthorizedException;
import com.ohgiraffers.tomatolab_imean.couple.model.dto.request.CoupleRegisterRequestDTO;
import com.ohgiraffers.tomatolab_imean.couple.model.dto.response.CoupleInfoResponseDTO;
import com.ohgiraffers.tomatolab_imean.couple.model.dto.response.CoupleResponseDTO;
import com.ohgiraffers.tomatolab_imean.couple.model.entity.Couple;
import com.ohgiraffers.tomatolab_imean.couple.service.CoupleService;
import com.ohgiraffers.tomatolab_imean.members.model.entity.Members;
import com.ohgiraffers.tomatolab_imean.members.service.MembersService;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.crossstore.ChangeSetPersister.NotFoundException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import java.util.Optional;

@RestController
@RequestMapping("/api/couple")
public class CoupleApiController {

    private final CoupleService coupleService;
    private final MembersService membersService;

    @Autowired
    public CoupleApiController(CoupleService coupleService, MembersService membersService) {
        this.coupleService = coupleService;
        this.membersService = membersService;
    }

    /**
     * 현재 사용자의 커플 상태 확인
     */
    @GetMapping("/status")
    public ResponseEntity<ApiResponseDTO<Boolean>> checkCoupleStatus(Authentication authentication) {
        try {
            Members currentMember = getCurrentMember(authentication);
            boolean isInCouple = coupleService.isAlreadyInCouple(currentMember);
            
            return ResponseEntity.ok(ApiResponseDTO.success("커플 상태 조회 성공", isInCouple));
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(ApiResponseDTO.error("인증이 필요합니다: " + e.getMessage()));
        }
    }

    /**
     * 커플 등록 요청
     */
    @PostMapping("/register")
    public ResponseEntity<ApiResponseDTO<CoupleResponseDTO>> registerCouple(
            @RequestBody CoupleRegisterRequestDTO requestDTO,
            Authentication authentication,
            HttpServletRequest request) {
        try {
            System.out.println("커플 등록 API 호출됨 - URL: " + request.getRequestURI());
            System.out.println("인증 상태: " + (authentication != null ? "인증됨" : "인증되지 않음"));
            
            if (authentication == null || !authentication.isAuthenticated()) {
                System.out.println("인증 정보 없음 - 세션 ID: " + request.getSession(false) != null ? request.getSession().getId() : "세션 없음");
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                        .body(ApiResponseDTO.error("인증이 필요합니다. 로그인 후 다시 시도해주세요."));
            }
            
            Members currentMember = getCurrentMember(authentication);
            System.out.println("현재 회원: ID=" + currentMember.getMembersId() + ", Code=" + currentMember.getMembersCode());
            System.out.println("대상 회원 코드: " + requestDTO.getTargetMemberCode());
            
            Couple couple = coupleService.registerCouple(currentMember, requestDTO.getTargetMemberCode());
            CoupleResponseDTO responseDTO = new CoupleResponseDTO(couple);
            
            System.out.println("커플 등록 성공: " + couple.getCoupleCode());
            return ResponseEntity.ok(ApiResponseDTO.success("커플 등록 성공", responseDTO));
        } catch (IllegalArgumentException e) {
            System.out.println("커플 등록 실패 (IllegalArgumentException): " + e.getMessage());
            return ResponseEntity.badRequest()
                    .body(ApiResponseDTO.error("요청 오류: " + e.getMessage()));
        } catch (IllegalStateException e) {
            System.out.println("커플 등록 실패 (IllegalStateException): " + e.getMessage());
            return ResponseEntity.status(HttpStatus.CONFLICT)
                    .body(ApiResponseDTO.error("상태 오류: " + e.getMessage()));
        } catch (NotFoundException e) {
            System.out.println("커플 등록 실패 (NotFoundException): " + e.getMessage());
            return ResponseEntity.status(HttpStatus.NOT_FOUND)
                    .body(ApiResponseDTO.error("찾을 수 없음: " + e.getMessage()));
        } catch (Exception e) {
            System.out.println("커플 등록 실패 (Exception): " + e.getClass().getName() + " - " + e.getMessage());
            e.printStackTrace();
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(ApiResponseDTO.error("서버 오류: " + e.getMessage()));
        }
    }

    /**
     * 커플 정보 조회
     */
    @GetMapping("/info")
    public ResponseEntity<ApiResponseDTO<CoupleInfoResponseDTO>> getCoupleInfo(Authentication authentication) {
        try {
            Members currentMember = getCurrentMember(authentication);
            Optional<Couple> coupleOptional = coupleService.findCoupleByMember(currentMember);
            
            if (coupleOptional.isPresent()) {
                Couple couple = coupleOptional.get();
                Members partner = coupleService.getPartner(couple, currentMember);
                
                CoupleInfoResponseDTO responseDTO = new CoupleInfoResponseDTO(couple, currentMember, partner);
                return ResponseEntity.ok(ApiResponseDTO.success("커플 정보 조회 성공", responseDTO));
            } else {
                return ResponseEntity.ok(ApiResponseDTO.error("커플 관계가 존재하지 않습니다"));
            }
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(ApiResponseDTO.error("서버 오류: " + e.getMessage()));
        }
    }

    /**
     * 현재 로그인한 회원 정보 조회 헬퍼 메서드
     */
    private Members getCurrentMember(Authentication authentication) throws NotFoundException {
        if (authentication == null || !authentication.isAuthenticated()) {
            System.out.println("getCurrentMember - 인증 객체 없음 또는 인증되지 않음");
            throw new UnauthorizedException("인증이 필요합니다");
        }
        
        try {
            if (!(authentication.getPrincipal() instanceof AuthDetails)) {
                System.out.println("getCurrentMember - 인증 객체가 AuthDetails 타입이 아님: " + authentication.getPrincipal().getClass().getName());
                throw new UnauthorizedException("잘못된 인증 타입입니다");
            }
            
            AuthDetails authDetails = (AuthDetails) authentication.getPrincipal();
            System.out.println("getCurrentMember - 인증된 사용자 코드: " + authDetails.getMembersCode());
            
            Members member = membersService.findByCode(authDetails.getMembersCode());
            System.out.println("getCurrentMember - 회원 찾음: " + member.getMembersId());
            return member;
        } catch (NotFoundException e) {
            System.out.println("getCurrentMember - 회원 정보를 찾을 수 없음");
            throw new UnauthorizedException("회원 정보를 찾을 수 없습니다");
        } catch (Exception e) {
            System.out.println("getCurrentMember - 예외 발생: " + e.getMessage());
            e.printStackTrace();
            throw new UnauthorizedException("인증 처리 중 오류 발생: " + e.getMessage());
        }
    }
}