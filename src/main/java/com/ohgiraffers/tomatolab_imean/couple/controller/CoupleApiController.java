package com.ohgiraffers.tomatolab_imean.couple.controller;

import com.ohgiraffers.tomatolab_imean.auth.model.AuthDetails;
import com.ohgiraffers.tomatolab_imean.auth.model.dto.response.LoginResponseDTO;
import com.ohgiraffers.tomatolab_imean.common.dto.response.ApiResponseDTO;
import com.ohgiraffers.tomatolab_imean.common.exception.UnauthorizedException;
import com.ohgiraffers.tomatolab_imean.couple.model.dto.request.CoupleRegisterRequestDTO;
import com.ohgiraffers.tomatolab_imean.couple.model.dto.response.CoupleInfoResponseDTO;
import com.ohgiraffers.tomatolab_imean.couple.model.dto.response.CoupleResponseDTO;
import com.ohgiraffers.tomatolab_imean.couple.model.entity.Couple;
import com.ohgiraffers.tomatolab_imean.couple.service.CoupleService;
import com.ohgiraffers.tomatolab_imean.members.model.dto.response.MemberResponseDTO;
import com.ohgiraffers.tomatolab_imean.members.model.entity.Members;
import com.ohgiraffers.tomatolab_imean.members.service.MemberService;
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
    private final MemberService memberService;
    private final com.ohgiraffers.tomatolab_imean.auth.jwt.JwtTokenProvider jwtTokenProvider;
    private final com.ohgiraffers.tomatolab_imean.auth.service.RefreshTokenService refreshTokenService;

    @Autowired
    public CoupleApiController(CoupleService coupleService, MemberService memberService,
                              com.ohgiraffers.tomatolab_imean.auth.jwt.JwtTokenProvider jwtTokenProvider,
                              com.ohgiraffers.tomatolab_imean.auth.service.RefreshTokenService refreshTokenService) {
        this.coupleService = coupleService;
        this.memberService = memberService;
        this.jwtTokenProvider = jwtTokenProvider;
        this.refreshTokenService = refreshTokenService;
    }

    /**
     * 현재 사용자의 커플 상태 확인
     */
    @GetMapping("/status")
    public ResponseEntity<ApiResponseDTO<Boolean>> checkCoupleStatus(Authentication authentication) {
        try {
            Long coupleId = findCoupleId(authentication);
            boolean isInCouple = (coupleId != null);
            
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
    public ResponseEntity<ApiResponseDTO<LoginResponseDTO>> registerCouple(
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
            
            // 헬퍼 메서드를 활용해서 이미 커플인지 미리 확인
            Long existingCoupleId = findCoupleId(authentication);
            if (existingCoupleId != null) {
                return ResponseEntity.status(HttpStatus.CONFLICT)
                        .body(ApiResponseDTO.error("이미 커플 관계에 있습니다. (커플 ID: " + existingCoupleId + ")"));
            }
            
            Members currentMember = getCurrentMember(authentication);
            System.out.println("현재 회원: ID=" + currentMember.getMemberId() + ", Code=" + currentMember.getMemberCode());
            System.out.println("대상 회원 코드: " + requestDTO.getTargetMemberCode());
            
            // 커플 등록 처리
            Couple couple = coupleService.registerCouple(currentMember, requestDTO.getTargetMemberCode());
            
            // 커플 등록 후 회원 정보 재조회 (coupleId가 업데이트됨)
            Members updatedMember = memberService.findByCode(currentMember.getMemberCode());
            
            // 새로운 JWT 토큰 발급 (COUPLED 상태로)
            String newAccessToken = jwtTokenProvider.createAccessToken(
                updatedMember.getMemberCode(),
                updatedMember.getCoupleStatusString(), // 이제 "COUPLED"
                updatedMember.getMemberRole().name()
            );
            String newRefreshToken = refreshTokenService.createAndSaveRefreshToken(updatedMember.getMemberCode());
            
            // 토큰 만료 시간 계산
            long expiresIn = jwtTokenProvider.getJwtProperties().getAccessTokenExpiration() / 1000;
            
            // 사용자 정보 생성
            MemberResponseDTO memberInfo = new MemberResponseDTO(updatedMember);
            
            // 응답 DTO 생성 (커플 정보 + 새로운 토큰)
            LoginResponseDTO loginResponse = new LoginResponseDTO(
                newAccessToken, 
                newRefreshToken, 
                expiresIn, 
                memberInfo
            );

            return ResponseEntity.ok(ApiResponseDTO.success("커플 등록 성공! 새로운 토큰이 발급되었습니다.", loginResponse));
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
     * 현재 사용자의 커플 ID 조회 (헬퍼 메서드)
     */
    private Long findCoupleId(Authentication authentication) throws NotFoundException {
        Members currentMember = getCurrentMember(authentication);
        Optional<Couple> coupleOptional = coupleService.findCoupleByMember(currentMember);
        
        if (coupleOptional.isPresent()) {
            return coupleOptional.get().getCoupleId();
        } else {
            return null; // 커플 관계가 없음
        }
    }
    
    /**
     * 현재 사용자의 커플 엔티티 조회 (헬퍼 메서드)
     */
    private Optional<Couple> findCouple(Authentication authentication) throws NotFoundException {
        Members currentMember = getCurrentMember(authentication);
        return coupleService.findCoupleByMember(currentMember);
    }

    /**
     * 현재 사용자의 커플 ID 조회 (API)
     */
    @GetMapping("/id")
    public ResponseEntity<ApiResponseDTO<Long>> getCoupleId(Authentication authentication) {
        try {
            Long coupleId = findCoupleId(authentication);
            
            if (coupleId != null) {
                return ResponseEntity.ok(ApiResponseDTO.success("커플 ID 조회 성공", coupleId));
            } else {
                return ResponseEntity.ok(ApiResponseDTO.success("커플 관계가 존재하지 않습니다", null));
            }
        } catch (UnauthorizedException e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(ApiResponseDTO.error("인증이 필요합니다: " + e.getMessage()));
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
            Optional<Couple> coupleOptional = findCouple(authentication);
            
            if (coupleOptional.isPresent()) {
                Couple couple = coupleOptional.get();
                Members currentMember = getCurrentMember(authentication);
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
     * 특정 커플 정보 조회 (커플 ID로)
     */
    @GetMapping("/{coupleId}")
    public ResponseEntity<ApiResponseDTO<CoupleInfoResponseDTO>> getCoupleById(
            @PathVariable Long coupleId, 
            Authentication authentication) {
        try {
            Members currentMember = getCurrentMember(authentication);
            
            // 커플 정보 조회
            Optional<Couple> coupleOptional = coupleService.findCoupleId(coupleId);
            if (coupleOptional.isEmpty()) {
                return ResponseEntity.status(HttpStatus.NOT_FOUND)
                        .body(ApiResponseDTO.error("커플을 찾을 수 없습니다"));
            }
            
            Couple couple = coupleOptional.get();
            
            // 권한 검증: 해당 커플의 멤버인지 확인
            boolean isAuthorized = couple.getMember1().getMemberId().equals(currentMember.getMemberId()) ||
                                  couple.getMember2().getMemberId().equals(currentMember.getMemberId());
            
            if (!isAuthorized) {
                return ResponseEntity.status(HttpStatus.FORBIDDEN)
                        .body(ApiResponseDTO.error("해당 커플 정보에 접근할 권한이 없습니다"));
            }
            
            Members partner = coupleService.getPartner(couple, currentMember);
            CoupleInfoResponseDTO responseDTO = new CoupleInfoResponseDTO(couple, currentMember, partner);
            
            return ResponseEntity.ok(ApiResponseDTO.success("커플 정보 조회 성공", responseDTO));
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(ApiResponseDTO.error("서버 오류: " + e.getMessage()));
        }
    }

    /**
     * 커플 해제
     */
    @DeleteMapping("/break")
    public ResponseEntity<ApiResponseDTO<LoginResponseDTO>> breakCouple(Authentication authentication) {
        try {
            Members currentMember = getCurrentMember(authentication);
            
            // 현재 커플 관계 확인
            Long coupleId = findCoupleId(authentication);
            if (coupleId == null) {
                return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                        .body(ApiResponseDTO.error("현재 커플 관계가 존재하지 않습니다"));
            }
            
            // 커플 해제 처리
            coupleService.breakCouple(currentMember);
            
            // 커플 해제 후 회원 정보 재조회 (coupleId가 null로 변경됨)
            Members updatedMember = memberService.findByCode(currentMember.getMemberCode());
            
            // 새로운 JWT 토큰 발급 (SINGLE 상태로)
            String newAccessToken = jwtTokenProvider.createAccessToken(
                updatedMember.getMemberCode(),
                updatedMember.getCoupleStatusString(), // 이제 "SINGLE"
                updatedMember.getMemberRole().name()
            );
            String newRefreshToken = refreshTokenService.createAndSaveRefreshToken(updatedMember.getMemberCode());
            
            // 토큰 만료 시간 계산
            long expiresIn = jwtTokenProvider.getJwtProperties().getAccessTokenExpiration() / 1000;
            
            // 사용자 정보 생성
            MemberResponseDTO memberInfo = new MemberResponseDTO(updatedMember);
            
            // 응답 DTO 생성 (새로운 토큰 포함)
            LoginResponseDTO loginResponse = new LoginResponseDTO(
                newAccessToken, 
                newRefreshToken, 
                expiresIn, 
                memberInfo
            );

            return ResponseEntity.ok(ApiResponseDTO.success("커플 해제 완료. 새로운 토큰이 발급되었습니다.", loginResponse));
        } catch (IllegalStateException e) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body(ApiResponseDTO.error("해제 오류: " + e.getMessage()));
        } catch (NotFoundException e) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND)
                    .body(ApiResponseDTO.error("커플 정보를 찾을 수 없습니다: " + e.getMessage()));
        } catch (Exception e) {
            System.out.println("커플 해제 실패 (Exception): " + e.getClass().getName() + " - " + e.getMessage());
            e.printStackTrace();
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
            System.out.println("getCurrentMember - 인증된 사용자 코드: " + authDetails.getMemberCode());
            
            Members member = memberService.findByCode(authDetails.getMemberCode());
            System.out.println("getCurrentMember - 회원 찾음: " + member.getMemberId());
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