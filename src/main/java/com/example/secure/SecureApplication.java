package com.example.secure;

import org.springframework.beans.factory.InitializingBean;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;

@SpringBootApplication
public class SecureApplication implements InitializingBean {

    @Autowired
    MemberRepository memberRepository;

    public static void main(String[] args) {
        SpringApplication.run(SecureApplication.class, args);
    }

    @Override
    public void afterPropertiesSet() throws Exception {
        PasswordEncoder passwordEncoder = PasswordEncoderFactories.createDelegatingPasswordEncoder();
        Member member = new Member();
        member.setUsername("user");
        member.setPassword(passwordEncoder.encode("password"));
        member.setAuthority("USER");
        memberRepository.save(member);
    }
}
