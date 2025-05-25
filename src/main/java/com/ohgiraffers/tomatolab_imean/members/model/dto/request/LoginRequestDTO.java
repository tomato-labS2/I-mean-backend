package com.ohgiraffers.tomatolab_imean.members.model.dto.request;

public class LoginRequestDTO {
    private String membersEmail;
    private String membersPass;
    
    // 생성자
    public LoginRequestDTO() {
    }
    
    public LoginRequestDTO(String membersEmail, String membersPass) {
        this.membersEmail = membersEmail;
        this.membersPass = membersPass;
    }
    
    // getter, setter
    public String getMembersEmail() {
        return membersEmail;
    }
    
    public void setMembersEmail(String membersEmail) {
        this.membersEmail = membersEmail;
    }
    
    public String getMembersPass() {
        return membersPass;
    }
    
    public void setMembersPass(String membersPass) {
        this.membersPass = membersPass;
    }
    
    // 이전 버전 호환성 유지
    public String getMembersCode() {
        return null;
    }
}