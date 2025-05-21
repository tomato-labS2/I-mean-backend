package com.ohgiraffers.tomatolab_imean.members.model.dto.response;

import com.ohgiraffers.tomatolab_imean.members.model.entity.Members;

import java.time.LocalDateTime;

public class MemberResponseDTO {
    private String membersCode;
    private String membersNickName;
    private String membersEmail;
    private LocalDateTime membersCreatedAt;
    
    // 생성자
    public MemberResponseDTO() {
    }
    
    public MemberResponseDTO(Members member) {
        this.membersCode = member.getMembersCode();
        this.membersNickName = member.getMembersNickName();
        this.membersEmail = member.getMembersEmail();
        this.membersCreatedAt = member.getMembersCreatedAt();
    }
    
    // getter, setter
    public String getMembersCode() {
        return membersCode;
    }

    public void setMembersCode(String membersCode) {
        this.membersCode = membersCode;
    }

    public String getMembersNickName() {
        return membersNickName;
    }

    public void setMembersNickName(String membersNickName) {
        this.membersNickName = membersNickName;
    }

    public String getMembersEmail() {
        return membersEmail;
    }

    public void setMembersEmail(String membersEmail) {
        this.membersEmail = membersEmail;
    }

    public LocalDateTime getMembersCreatedAt() {
        return membersCreatedAt;
    }

    public void setMembersCreatedAt(LocalDateTime membersCreatedAt) {
        this.membersCreatedAt = membersCreatedAt;
    }
}