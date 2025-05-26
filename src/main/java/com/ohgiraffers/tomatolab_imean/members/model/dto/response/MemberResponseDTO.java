package com.ohgiraffers.tomatolab_imean.members.model.dto.response;

import com.ohgiraffers.tomatolab_imean.members.model.entity.Members;

import java.time.LocalDateTime;

public class MemberResponseDTO {
    private String memberCode;
    private String memberNickName;
    private String memberEmail;
    private LocalDateTime memberCreatedAt;
    
    // 생성자
    public MemberResponseDTO() {
    }
    
    public MemberResponseDTO(Members member) {
        this.memberCode = member.getMemberCode();
        this.memberNickName = member.getMemberNickName();
        this.memberEmail = member.getMemberEmail();
        this.memberCreatedAt = member.getMemberCreatedAt();
    }
    
    // getter, setter
    public String getMemberCode() {
        return memberCode;
    }

    public void setMemberCode(String memberCode) {
        this.memberCode = memberCode;
    }

    public String getMemberNickName() {
        return memberNickName;
    }

    public void setMemberNickName(String memberNickName) {
        this.memberNickName = memberNickName;
    }

    public String getMemberEmail() {
        return memberEmail;
    }

    public void setMemberEmail(String memberEmail) {
        this.memberEmail = memberEmail;
    }

    public LocalDateTime getMemberCreatedAt() {
        return memberCreatedAt;
    }

    public void setMemberCreatedAt(LocalDateTime memberCreatedAt) {
        this.memberCreatedAt = memberCreatedAt;
    }
}