package com.ohgiraffers.tomatolab_imean.auth.model.dto.request;

public class LoginRequestDTO {
    private String membersCode;
    private String membersPass;
    
    // 생성자, getter, setter
    public LoginRequestDTO() {
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
}