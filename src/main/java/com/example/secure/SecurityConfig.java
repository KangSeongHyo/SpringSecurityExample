package com.example.secure;

import lombok.RequiredArgsConstructor;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.authority.mapping.SimpleAuthorityMapper;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

@RequiredArgsConstructor
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    private final UserDetailsService userDetailsService;
    private static final RequestMatcher LOGIN_REQUEST_MATCHER = new AntPathRequestMatcher("/api/v1/login","POST");


    @Override
    protected void configure(AuthenticationManagerBuilder auth){
        auth.authenticationProvider(new IdPwAuthenticationProvider(userDetailsService,PasswordEncoderFactories.createDelegatingPasswordEncoder(),new SimpleAuthorityMapper()));
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {

        JsonIdPwAuthenticationFilter jsonAuthenticationFilter = new JsonIdPwAuthenticationFilter(LOGIN_REQUEST_MATCHER);
        jsonAuthenticationFilter.setAuthenticationManager(authenticationManagerBean());

        http.csrf().disable();
        http.addFilterAt(jsonAuthenticationFilter,UsernamePasswordAuthenticationFilter.class);
        // http.userDetailsService(userDetailsService);
    }

    @Override
    public void configure(WebSecurity web){
        web.debug(true);
    }
}
