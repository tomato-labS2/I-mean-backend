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
            Authentication authentication) {
        try {
            Members currentMember = getCurrentMember(authentication);
            Couple couple = coupleService.registerCouple(currentMember, requestDTO.getTargetMemberCode());
            CoupleResponseDTO responseDTO = new CoupleResponseDTO(couple);
            
            return ResponseEntity.ok(ApiResponseDTO.success("커플 등록 성공", responseDTO));
        } catch (IllegalArgumentException e) {
            return ResponseEntity.badRequest()
                    .body(ApiResponseDTO.error("요청 오류: " + e.getMessage()));
        } catch (IllegalStateException e) {
            return ResponseEntity.status(HttpStatus.CONFLICT)
                    .body(ApiResponseDTO.error("상태 오류: " + e.getMessage()));
        } catch (NotFoundException e) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND)
                    .body(ApiResponseDTO.error("찾을 수 없음: " + e.getMessage()));
        } catch (Exception e) {
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
            throw new UnauthorizedException("인증이 필요합니다");
        }
        
        AuthDetails authDetails = (AuthDetails) authentication.getPrincipal();
        return membersService.findByCode(authDetails.getMembersCode());
    }
}