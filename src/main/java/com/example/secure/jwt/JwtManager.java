package com.example.secure.jwt;

import com.google.gson.Gson;
import com.google.gson.JsonObject;
import org.springframework.security.jwt.Jwt;
import org.springframework.security.jwt.JwtHelper;
import org.springframework.security.jwt.crypto.sign.MacSigner;

public class JwtManager {

    private static final MacSigner macSigner = new MacSigner("will-b-fine");
    private static final Gson gson = new Gson();

    public static Jwt createJwt(String id){

        return JwtHelper.encode(createPayload(id), macSigner);
    }

    private static String createPayload(String id){

        JsonObject jsonObject = new JsonObject();
        jsonObject.addProperty("id", id);
        jsonObject.addProperty("iat",getIssueAt());

        return gson.toJson(jsonObject);
    }

    private static long getIssueAt(){
        return System.currentTimeMillis();
    }
}
