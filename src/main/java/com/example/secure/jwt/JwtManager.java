package com.example.secure.jwt;

import com.google.gson.Gson;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import org.springframework.security.jwt.Jwt;
import org.springframework.security.jwt.JwtHelper;
import org.springframework.security.jwt.crypto.sign.MacSigner;

import java.time.Instant;
import java.time.LocalDateTime;
import java.util.TimeZone;

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

    public static boolean validateJwt(String jwt){

        JsonObject jsonObject = getJsonObject(jwt);
        JsonElement iatJson = jsonObject.get("iat");

        long iat = iatJson.getAsLong();
        LocalDateTime iatDateTime = LocalDateTime.ofInstant(Instant.ofEpochMilli(iat), TimeZone.getDefault().toZoneId());

        return iatDateTime.plusMinutes(30).isAfter(LocalDateTime.now());
    }

    public static String getInfo(String jwt, String attr){
        JsonObject jsonObject = getJsonObject(jwt);
        JsonElement jsonElement = jsonObject.get(attr);

        return jsonElement.getAsString();
    }

    private static JsonObject getJsonObject(String jwt) {
        Jwt decodedJwt = JwtHelper.decodeAndVerify(jwt, macSigner);

        String claims = decodedJwt.getClaims();
        return gson.fromJson(claims, JsonObject.class);
    }
}
