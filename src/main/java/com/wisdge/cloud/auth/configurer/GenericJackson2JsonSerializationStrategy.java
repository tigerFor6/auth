package com.wisdge.cloud.auth.configurer;

import org.springframework.data.redis.serializer.GenericJackson2JsonRedisSerializer;
import org.springframework.security.oauth2.provider.token.store.redis.StandardStringSerializationStrategy;
import org.springframework.stereotype.Component;

@Component
public class GenericJackson2JsonSerializationStrategy extends StandardStringSerializationStrategy {

    private static final GenericJackson2JsonRedisSerializer JSON_REDIS_SERIALIZER = new GenericJackson2JsonRedisSerializer();

    @Override
    protected <T> T deserializeInternal(byte[] bytes, Class<T> clazz) {
        return JSON_REDIS_SERIALIZER.deserialize(bytes, clazz);
    }

    @Override
    protected byte[] serializeInternal(Object object) {
        return JSON_REDIS_SERIALIZER.serialize(object);
    }
}
