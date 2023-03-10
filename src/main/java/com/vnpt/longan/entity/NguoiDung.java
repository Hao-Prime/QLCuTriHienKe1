package com.vnpt.longan.entity;

import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import com.fasterxml.jackson.databind.ser.std.ToStringSerializer;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.bson.types.ObjectId;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.Document;

import java.util.List;

@Document(collection = "User")
@Data
@NoArgsConstructor
@AllArgsConstructor
public class NguoiDung {
    @Id
    @JsonSerialize(using= ToStringSerializer.class)
    private ObjectId _id;
    private String idGGFB;
    private String hoTen;
    private String urlAvater;
    private String email;
    private String soDienThoai;
    private String password;
    private List<String> listRoles;
}
