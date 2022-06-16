package com.wisdge.cloud.auth.exception;

import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.databind.SerializerProvider;
import com.fasterxml.jackson.databind.ser.std.StdSerializer;
import com.wisdge.cloud.dto.ApiResult;
import org.springframework.http.HttpStatus;

import java.io.IOException;
import java.util.Map;

/**
 * @description: 异常json序列化方式
 */
public class CustomOauthExceptionSerializer extends StdSerializer<CustomOauth2Exception> {
    protected CustomOauthExceptionSerializer() {
        super(CustomOauth2Exception.class);
    }

    @Override
    public void serialize(CustomOauth2Exception exception, JsonGenerator gen, SerializerProvider serializerProvider) throws IOException {
        gen.writeStartObject();
        gen.writeNumberField("code", exception.getCode());
        // gen.writeStringField("message", "用户名或密码错误");
        gen.writeStringField("message", exception.getMessage());
        if (exception.getAdditionalInformation() != null) {
            for (Map.Entry<String, String> entry : exception.getAdditionalInformation().entrySet()) {
                String key = entry.getKey();
                String add = entry.getValue();
                gen.writeStringField(key, add);
            }
        }
        gen.writeEndObject();
    }
}
