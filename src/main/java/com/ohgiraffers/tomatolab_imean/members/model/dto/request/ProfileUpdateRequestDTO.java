package com.ohgiraffers.tomatolab_imean.members.model.dto.request;

public class ProfileUpdateRequestDTO {
    private String currentPassword; // 현재 비밀번호 (변경 시 필요)
    private String newPassword;     // 새 비밀번호 (선택적)
    private String membersEmail;
    private String membersPhone;
    
    // 생성자
    public ProfileUpdateRequestDTO() {
    }
    
    public ProfileUpdateRequestDTO(String currentPassword, String newPassword, 
                              String membersEmail, String membersPhone) {
        this.currentPassword = currentPassword;
        this.newPassword = newPassword;
        this.membersEmail = membersEmail;
        this.membersPhone = membersPhone;
    }
    
    // getter, setter
    public String getCurrentPassword() {
        return currentPassword;
    }

    public void setCurrentPassword(String currentPassword) {
        this.currentPassword = currentPassword;
    }

    public String getNewPassword() {
        return newPassword;
    }

    public void setNewPassword(String newPassword) {
        this.newPassword = newPassword;
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