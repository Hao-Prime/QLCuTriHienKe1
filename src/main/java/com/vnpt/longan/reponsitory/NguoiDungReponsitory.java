package com.vnpt.longan.reponsitory;

import com.vnpt.longan.entity.NguoiDung;
import org.bson.types.ObjectId;
import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.data.mongodb.repository.Query;
import org.springframework.stereotype.Repository;

@Repository
public interface NguoiDungReponsitory extends MongoRepository<NguoiDung, ObjectId> {
    @Query("{ '_id' : ?0 }")
    NguoiDung timTheoID(String id);
    @Query("{ '_id' : ?0 }")
    NguoiDung timTheoSDT(String sdt);
    @Query("{ 'idGGFB' : ?0 }")
    NguoiDung timTheoIGGFB(String idGGFB);
}