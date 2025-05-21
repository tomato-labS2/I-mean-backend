package com.ohgiraffers.tomatolab_imean.auth.model.dto.request;

public class RegisterRequestDTO {
    private String membersCode;
    private String membersPass;
    private String membersNickName;
    private String membersEmail;
    private String membersPhone;
    
    // 생성자, getter, setter
    public RegisterRequestDTO() {
    }

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