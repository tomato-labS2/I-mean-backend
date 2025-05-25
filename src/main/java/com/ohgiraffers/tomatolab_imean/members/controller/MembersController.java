package com.ohgiraffers.tomatolab_imean.members.controller;

import com.ohgiraffers.tomatolab_imean.auth.model.AuthDetails;
import com.ohgiraffers.tomatolab_imean.auth.service.AuthService;
import com.ohgiraffers.tomatolab_imean.common.dto.response.ApiResponseDTO;
import com.ohgiraffers.tomatolab_imean.common.exception.UnauthorizedException;
import com.ohgiraffers.tomatolab_imean.members.model.common.MembersStatus;
import com.ohgiraffers.tomatolab_imean.members.model.dto.request.LoginRequestDTO;
import com.ohgiraffers.tomatolab_imean.members.model.dto.request.ProfileUpdateRequestDTO;
import com.ohgiraffers.tomatolab_imean.members.model.dto.request.RegisterRequestDTO;
import com.ohgiraffers.tomatolab_imean.members.model.dto.response.MemberResponseDTO;
import com.ohgiraffers.tomatolab_imean.members.model.entity.Members;
import com.ohgiraffers.tomatolab_imean.members.service.MembersService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.crossstore.ChangeSetPersister;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.parameters.P;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.util.Random;

@RestController
@RequestMapping("/api/members")
public class MembersController {
    
    private final MembersService membersService;
    private final AuthService authService;
    private final AuthenticationManager authenticationManager;
    private final PasswordEncoder passwordEncoder;
    
    @Autowired
    public MembersController(MembersService membersService,
                             AuthService authService,
                             AuthenticationManager authenticationManager,
                             PasswordEncoder passwordEncoder) {
        this.membersService = membersService;
        this.authService = authService;
        this.authenticationManager = authenticationManager;
        this.passwordEncoder = passwordEncoder;
    }
    
    /**
     * 로그인 처리
     */
    @PostMapping("/login")
    public ResponseEntity<ApiResponseDTO<MemberResponseDTO>> login(
            @RequestBody LoginRequestDTO request, 
            HttpServletRequest httpRequest) {
        try {
            // 이메일로 사용자 찾기
            Members member;
            try {
                member = membersService.findByEmail(request.getMembersEmail());
            } catch (ChangeSetPersister.NotFoundException e) {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                        .body(ApiResponseDTO.error("로그인 실패: 이메일 또는 비밀번호가 일치하지 않습니다."));
            }
            
            // Spring Security 인증
            Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(member.getMembersCode(), request.getMembersPass())
            );
            
            SecurityContextHolder.getContext().setAuthentication(authentication);
            
            // 세션에 인증 정보를 명시적으로 저장
            httpRequest.getSession(true).setAttribute(
                "SPRING_SECURITY_CONTEXT", 
                SecurityContextHolder.getContext()
            );
            
            // 세션 정보 로깅
            System.out.println("로그인 성공 - 세션 ID: " + httpRequest.getSession().getId());
            System.out.println("세션 신규 생성: " + httpRequest.getSession().isNew());
            
            // 사용자 정보 반환
            MemberResponseDTO responseDTO = new MemberResponseDTO(member);
            
            return ResponseEntity.ok(ApiResponseDTO.success("로그인 성공", responseDTO));
        } catch (AuthenticationException e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(ApiResponseDTO.error("로그인 실패: 이메일 또는 비밀번호가 일치하지 않습니다."));
        }
    }


    @PostMapping("/register/step1")
    public ResponseEntity<ApiResponseDTO<String>> step1(HttpServletRequest request, @RequestBody RegisterRequestDTO requestdto) {
        HttpSession session = request.getSession(true);
        if (requestdto.getMembersEmail() == null || requestdto.getMembersEmail().isEmpty()) {
            return ResponseEntity.badRequest().body(ApiResponseDTO.error("이메일을 입력해주세요"));
        }

        session.setAttribute("membersEmail",requestdto.getMembersEmail() );



        return ResponseEntity.ok(
                ApiResponseDTO.success("이메일 저장완료", requestdto.getMembersPass()));
    }
    @PostMapping("/register/step2")
    public ResponseEntity<ApiResponseDTO<String>> step2(HttpServletRequest request, @RequestBody RegisterRequestDTO requestdto) {
        HttpSession session = request.getSession(false);


        if (session.getAttribute("membersEmail") == null) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body(ApiResponseDTO.error("세션이 만료되었거나 첫 단계부터 시작해주세요"));
        }

        // 비밀번호 검증 로직
        if (requestdto.getMembersPass() == null || requestdto.getMembersPass().isEmpty()) {
            return ResponseEntity.badRequest().body(ApiResponseDTO.error("비밀번호를 입력해주세요"));
        }
        session.setAttribute("membersNickName",requestdto.getMembersNickName() );


        return ResponseEntity.ok(
                ApiResponseDTO.success("닉네임 저장 완료", requestdto.getMembersNickName()));
    }
    @PostMapping("/register/step3")
    public ResponseEntity<ApiResponseDTO<String>> step3(HttpServletRequest request, @RequestBody RegisterRequestDTO requestdto) {

        HttpSession session = request.getSession(false);

        if (requestdto.getMembersPass() == null || requestdto.getMembersPass().isEmpty()) {
            return ResponseEntity.badRequest().body(ApiResponseDTO.error("비밀번호를 입력해주세요"));
        }
        session.setAttribute("membersPass",requestdto.getMembersPass() );


        return ResponseEntity.ok(
                ApiResponseDTO.success("비밀번호 저장 완료", requestdto.getMembersPass()));

    }


    @PostMapping("/register/step4")
    public ResponseEntity<ApiResponseDTO<MemberResponseDTO>> step4(
            HttpSession session, @RequestBody RegisterRequestDTO request) {

        // 이전 단계 데이터 확인
        String email = (String) session.getAttribute("membersEmail");
        String password = (String) session.getAttribute("membersPass");
        String nickname = (String) session.getAttribute("membersNickName");

        if (email == null || password == null || nickname == null) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body(ApiResponseDTO.error("세션이 만료되었거나 필수 정보가 누락되었습니다"));
        }

        // 전화번호 저장
        session.setAttribute("membersPhone", request.getMembersPhone());

        try {
            // 회원 코드 생성
            String membersCode = generateRandomMembersCode();

            // 회원 등록
            Members newMember = membersService.register(
                    membersCode,
                    password,
                    nickname,
                    email,
                    request.getMembersPhone()
            );

            // 회원가입 세션 데이터 정리
            session.removeAttribute("membersEmail");
            session.removeAttribute("membersPass");
            session.removeAttribute("membersNickName");
            session.removeAttribute("membersPhone");

            MemberResponseDTO responseDTO = new MemberResponseDTO(newMember);
            return ResponseEntity.ok(ApiResponseDTO.success("회원 가입 성공", responseDTO));
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(ApiResponseDTO.error("회원 가입 실패: " + e.getMessage()));
        }

    }
    /**
     * 회원 프로필 조회
     */
    @GetMapping("/profile")
    public ResponseEntity<ApiResponseDTO<MemberResponseDTO>> getProfile(Authentication authentication) {
        try {
            Members member = getCurrentMember(authentication);
            
            if (member.getMembersStatus() != MembersStatus.ACTIVE) {
                return ResponseEntity.status(HttpStatus.FORBIDDEN)
                        .body(ApiResponseDTO.error("계정이 활성화 상태가 아닙니다"));
            }
            
            MemberResponseDTO responseDTO = new MemberResponseDTO(member);
            return ResponseEntity.ok(ApiResponseDTO.success("프로필 조회 성공", responseDTO));
        } catch (UnauthorizedException e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(ApiResponseDTO.error(e.getMessage()));
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(ApiResponseDTO.error("서버 오류: " + e.getMessage()));
        }
    }
    
    /**
     * 비밀번호 확인
     */
    @PostMapping("/verify-password")
    public ResponseEntity<ApiResponseDTO<Boolean>> verifyPassword(
            Authentication authentication, 
            @RequestBody ProfileUpdateRequestDTO request) {
        try {
            Members member = getCurrentMember(authentication);
            
            if (member.getMembersStatus() != MembersStatus.ACTIVE) {
                return ResponseEntity.status(HttpStatus.FORBIDDEN)
                        .body(ApiResponseDTO.error("계정이 활성화 상태가 아닙니다"));
            }
            
            boolean isValid = passwordEncoder.matches(request.getCurrentPassword(), member.getMembersPass());
            
            if (isValid) {
                return ResponseEntity.ok(ApiResponseDTO.success("비밀번호 확인 성공", true));
            } else {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                        .body(ApiResponseDTO.error("비밀번호가 일치하지 않습니다"));
            }
        } catch (UnauthorizedException e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(ApiResponseDTO.error(e.getMessage()));
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(ApiResponseDTO.error("서버 오류: " + e.getMessage()));
        }
    }
    
    /**
     * 프로필 업데이트
     */
    @PutMapping("/profile")
    public ResponseEntity<ApiResponseDTO<MemberResponseDTO>> updateProfile(
            Authentication authentication,
            @RequestBody ProfileUpdateRequestDTO request) {
        try {
            Members member = getCurrentMember(authentication);
            
            if (member.getMembersStatus() != MembersStatus.ACTIVE) {
                return ResponseEntity.status(HttpStatus.FORBIDDEN)
                        .body(ApiResponseDTO.error("계정이 활성화 상태가 아닙니다"));
            }
            
            // 현재 비밀번호 확인 (비밀번호 변경 시에만)
            if (request.getNewPassword() != null && !request.getNewPassword().isEmpty()) {
                if (request.getCurrentPassword() == null || 
                    !passwordEncoder.matches(request.getCurrentPassword(), member.getMembersPass())) {
                    return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                            .body(ApiResponseDTO.error("현재 비밀번호가 일치하지 않습니다"));
                }
            }
            
            // 업데이트 처리
            Members updatedMember = membersService.updateMemberProfile(
                member.getMembersId(),
                request.getNewPassword(),
                request.getMembersEmail(),
                request.getMembersPhone()
            );
            
            MemberResponseDTO responseDTO = new MemberResponseDTO(updatedMember);
            
            // 비밀번호 변경한 경우 로그아웃 필요성 알림
            if (request.getNewPassword() != null && !request.getNewPassword().isEmpty()) {
                return ResponseEntity.ok(ApiResponseDTO.success(
                        "프로필 업데이트 성공. 비밀번호가 변경되었습니다. 다시 로그인해주세요.", 
                        responseDTO));
            } else {
                return ResponseEntity.ok(ApiResponseDTO.success("프로필 업데이트 성공", responseDTO));
            }
        } catch (UnauthorizedException e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(ApiResponseDTO.error(e.getMessage()));
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(ApiResponseDTO.error("서버 오류: " + e.getMessage()));
        }
    }
    
    /**
     * 현재 인증된 회원 정보 조회 헬퍼 메서드
     */
    private Members getCurrentMember(Authentication authentication) {
        if (authentication == null || !authentication.isAuthenticated()) {
            throw new UnauthorizedException("인증이 필요합니다");
        }
        
        try {
            AuthDetails authDetails = (AuthDetails) authentication.getPrincipal();
            return membersService.findByCode(authDetails.getMembersCode());
        } catch (ChangeSetPersister.NotFoundException e) {
            throw new UnauthorizedException("회원 정보를 찾을 수 없습니다");
        }
    }
    
    /**
     * 랜덤 회원 코드 생성
     */
    private String generateRandomMembersCode() {
        StringBuilder sb = new StringBuilder();
        String characters = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
        Random random = new Random();
        
        for (int i = 0; i < 10; i++) {
            int index = random.nextInt(characters.length());
            sb.append(characters.charAt(index));
        }
        
        return sb.toString();
    }
}