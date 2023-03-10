package com.vnpt.longan.dto.other;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class Token {
    private String access_token;
    private String userID;
    private String userName;
    private String avatarURL;
    private List<String> Roles;
}
