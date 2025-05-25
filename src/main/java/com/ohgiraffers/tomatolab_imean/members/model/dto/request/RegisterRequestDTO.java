package com.ohgiraffers.tomatolab_imean.members.model.dto.request;

public class RegisterRequestDTO {
    private String membersCode; // 선택적 - 제공되지 않으면 자동 생성
    private String membersPass;
    private String membersNickName;
    private String membersEmail;
    private String membersPhone;
    
    // 생성자
    public RegisterRequestDTO() {
    }
    
    public RegisterRequestDTO(String membersCode, String membersPass, String membersNickName, 
                          String membersEmail, String membersPhone) {
        this.membersCode = membersCode;
        this.membersPass = membersPass;
        this.membersNickName = membersNickName;
        this.membersEmail = membersEmail;
        this.membersPhone = membersPhone;
    }
    
    // getter, setter
    public String getMembersCode() {
        return membersCode;
    }

    public void setMembersCode(String membersCode) {
        this.membersCode = membersCode;
    }

    public String getMembersPass() {
        return membersPass;
    }

    public void setMembersPass(String membersPass) {
        this.membersPass = membersPass;
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

    public String getMembersPhone() {
        return membersPhone;
    }

    public void setMembersPhone(String membersPhone) {
        this.membersPhone = membersPhone;
    }
}