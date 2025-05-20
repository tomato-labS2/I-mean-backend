package com.ohgiraffers.tomatolab_imean.auth.model;

import com.ohgiraffers.tomatolab_imean.members.model.common.MembersRole;
import com.ohgiraffers.tomatolab_imean.members.model.common.MembersStatus;
import com.ohgiraffers.tomatolab_imean.members.model.dto.LoginMembersDTO;
import com.ohgiraffers.tomatolab_imean.members.model.dto.MembersDTO;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

public class AuthDetails implements UserDetails {

    private LoginMembersDTO loginMembersDTO;
    private MembersDTO membersDTO;

    public AuthDetails(LoginMembersDTO loginMembersDTO, MembersDTO membersDTO) {
        this.loginMembersDTO = loginMembersDTO;
        this.membersDTO = membersDTO;
    }

    public AuthDetails() {}

    public AuthDetails(LoginMembersDTO loginMembersDTO) {
        this.loginMembersDTO = loginMembersDTO;
    }

    public LoginMembersDTO getLoginMembersDTO() {
        return loginMembersDTO;
    }

    public void setLoginMembersDTO(LoginMembersDTO loginMembersDTO) {
        this.loginMembersDTO = loginMembersDTO;
    }

    // 권한 정보 반환
    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        List<GrantedAuthority> authorities = new ArrayList<>();

        MembersStatus status = loginMembersDTO.getMembersStatus();
        MembersRole role = loginMembersDTO.getMembersRole();

        // 기본 권한 추가
        authorities.add(new SimpleGrantedAuthority(status.toString()));

//        // 재직중 상태인 경우에만 추가 권한 부여
//        if (MembersStatus.재직중.toString().equals(status.toString())) {
//            // 통합 부서는 관리자 직책만 가질 수 있음
//            // 통합 부서 + 관리자인 경우 모든 도메인 접근 권한 부여
//            if ("통합".equals(part) && "관리자".equals(role.toString())) {
//                authorities.add(new SimpleGrantedAuthority("통합_관리자"));
//            }
//            // 일반 부서의 경우 부서 + 직책 조합으로 권한 부여
//            else {
//                authorities.add(new SimpleGrantedAuthority(part + "_" + role));
//            }
//        }

        return authorities;
    }

    // 비밀번호 반환
    @Override
    public String getPassword() {
        return loginMembersDTO.getMembersPass();
    }

    // 이름(유저코드) 반환
    @Override
    public String getUsername() {
        return loginMembersDTO.getMembersNickName();
    }

    // 계정 만료 여부를 표현하는 메서드
    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    // 잠겨있는 계정을 확인하는 메서드
    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    // 탈퇴 계정 여부를 표현하는 메서드
    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    // 계정 비활성화 여부로 사용자가 사용할 수 없는 상태
    @Override
    public boolean isEnabled() {
        return true;
    }

    public String getMembersCode() {
        return loginMembersDTO.getMembersCode();
    }

    // id 반환
    public Long getMembersId() {
        return loginMembersDTO.getMembersId();
    }
}