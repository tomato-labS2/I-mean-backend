package com.ohgiraffers.tomatolab_imean.auth.service;

import com.ohgiraffers.tomatolab_imean.auth.model.AuthDetails;
import com.ohgiraffers.tomatolab_imean.members.model.common.MemberStatus;
import com.ohgiraffers.tomatolab_imean.members.model.entity.Members;
import com.ohgiraffers.tomatolab_imean.members.service.MemberService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.crossstore.ChangeSetPersister;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
public class AuthService implements UserDetailsService {

    private final MemberService memberService;

    @Autowired
    public AuthService(MemberService memberService) {
        this.memberService = memberService;
    }

    /**
     * Spring Security 인증을 위한 사용자 정보 로드 메서드
     * membersCode를 기준으로 사용자를 검색하고 UserDetails 객체로 반환
     * usernamepasswordauthenticationtoken와 비교를 진행함
     *
     */
    @Override
    public UserDetails loadUserByUsername(String memberCode) throws UsernameNotFoundException {
        try {
            // membersCode로 회원 정보 조회
            Members member = memberService.findByCode(memberCode);
            
            // 계정 상태 확인
            checkAccountStatus(member);
            
            // AuthDetails 객체 생성 및 반환
            return createAuthDetails(member);
        } catch (ChangeSetPersister.NotFoundException e) {
            throw new UsernameNotFoundException("회원 정보가 존재하지 않습니다.");
        }
    }
    
    /**
     * 이메일로 사용자 인증 처리 (API 로그인용)
     */
    public UserDetails authenticateByEmail(String email, String password) {
        try {
            // 이메일로 회원 정보 조회
            Members member = memberService.findByEmail(email);
            
            // 계정 상태 확인
            checkAccountStatus(member);
            
            // 인증 성공 시 AuthDetails 객체 생성 및 반환
            return createAuthDetails(member);
        } catch (ChangeSetPersister.NotFoundException e) {
            throw new UsernameNotFoundException("회원 정보가 존재하지 않습니다.");
        }
    }
    
    /**
     * 계정 상태 검증 헬퍼 메서드
     */
    private void checkAccountStatus(Members member) {
        MemberStatus status = member.getMemberStatus();
        
        // 상태 체크 - ACTIVE가 아닌 경우 로그인 차단
        if (!com.ohgiraffers.tomatolab_imean.members.model.common.MemberStatus.ACTIVE.equals(status)) {
            if (com.ohgiraffers.tomatolab_imean.members.model.common.MemberStatus.DORMANT.equals(status)) {
                throw new LockedException("휴면 계정입니다. 관리자에게 문의하세요.");
            } else if (com.ohgiraffers.tomatolab_imean.members.model.common.MemberStatus.BLOCKED.equals(status)) {
                throw new LockedException("차단된 계정입니다. 관리자에게 문의하세요.");
            } else {
                throw new LockedException("비활성화된 계정입니다. 관리자에게 문의하세요.");
            }
        }
    }
    
    /**
     * AuthDetails 객체 생성 헬퍼 메서드
     */
    private AuthDetails createAuthDetails(Members member) {
        return new AuthDetails(
            member.getMemberId(),
            member.getMemberCode(),
            member.getMemberPass(),
            member.getMemberRole(),
            member.getMemberStatus()
        );
    }
}