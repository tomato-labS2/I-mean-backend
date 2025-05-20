package com.ohgiraffers.tomatolab_imean.members.model.dto;

public class SinupDTO {

    private String membersId;
    private String membersCode;
    private String membersNickName; // 변경된 부분: Name → NickName
    private String membersPassword;
    private String membersEmail;
    private String membersRole;
    private String membersPhone;
    private String membersStatus;

    public SinupDTO() {
    }

    public SinupDTO(String membersId, String membersCode, String membersNickName, String membersPassword, String membersEmail, String membersRole, String membersPhone, String membersStatus) {
        this.membersId = membersId;
        this.membersCode = membersCode;
        this.membersNickName = membersNickName;
        this.membersPassword = membersPassword;
        this.membersEmail = membersEmail;
        this.membersRole = membersRole;
        this.membersPhone = membersPhone;
        this.membersStatus = membersStatus;
    }

    public String getMembersId() {
        return membersId;
    }

    public void setMembersId(String membersId) {
        this.membersId = membersId;
    }

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

    public String getMembersPassword() {
        return membersPassword;
    }

    public void setMembersPassword(String membersPassword) {
        this.membersPassword = membersPassword;
    }

    public String getMembersEmail() {
        return membersEmail;
    }

    public void setMembersEmail(String membersEmail) {
        this.membersEmail = membersEmail;
    }

    public String getMembersRole() {
        return membersRole;
    }

    public void setMembersRole(String membersRole) {
        this.membersRole = membersRole;
    }

    public String getMembersPhone() {
        return membersPhone;
    }

    public void setMembersPhone(String membersPhone) {
        this.membersPhone = membersPhone;
    }

    public String getMembersStatus() {
        return membersStatus;
    }

    public void setMembersStatus(String membersStatus) {
        this.membersStatus = membersStatus;
    }

    @Override
    public String toString() {
        return "SinupDTO{" +
                "membersId='" + membersId + '\'' +
                ", membersCode='" + membersCode + '\'' +
                ", membersNickName='" + membersNickName + '\'' +
                ", membersPassword='" + membersPassword + '\'' +
                ", membersEmail='" + membersEmail + '\'' +
                ", membersRole='" + membersRole + '\'' +
                ", membersPhone='" + membersPhone + '\'' +
                ", membersStatus='" + membersStatus + '\'' +
                '}';
    }
}