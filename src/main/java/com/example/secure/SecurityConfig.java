package com.example.secure;

import com.example.secure.jwt.JwtAuthenticationFilter;
import com.example.secure.jwt.JwtSuccessHandler;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.authority.mapping.SimpleAuthorityMapper;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

@RequiredArgsConstructor
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    private final UserDetailsService userDetailsService;
    private final JwtAuthenticationFilter jwtAuthenticationFilter;
    private static final RequestMatcher LOGIN_REQUEST_MATCHER = new AntPathRequestMatcher("/api/v1/login","POST");


    @Override
    protected void configure(AuthenticationManagerBuilder auth){
        auth.authenticationProvider(new IdPwAuthenticationProvider(userDetailsService,PasswordEncoderFactories.createDelegatingPasswordEncoder(),new SimpleAuthorityMapper()));
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {

        http.csrf().disable();
        http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);
        http.authorizeRequests()
                .antMatchers("/api/v1/test").hasRole("USER");
        http.addFilterAt(jsonIdPwAuthenticationFilter(),UsernamePasswordAuthenticationFilter.class);
        http.addFilterBefore(jwtAuthenticationFilter, JsonIdPwAuthenticationFilter.class);
        http.userDetailsService(userDetailsService);
    }

    @Bean
    public JsonIdPwAuthenticationFilter jsonIdPwAuthenticationFilter() throws Exception {
        JsonIdPwAuthenticationFilter jsonAuthenticationFilter = new JsonIdPwAuthenticationFilter(LOGIN_REQUEST_MATCHER);
        jsonAuthenticationFilter.setAuthenticationManager(authenticationManagerBean());
        jsonAuthenticationFilter.setAuthenticationSuccessHandler(authenticationSuccessHandler());
        return jsonAuthenticationFilter;
    }

    @Bean
    public AuthenticationSuccessHandler authenticationSuccessHandler(){
        return new JwtSuccessHandler();
    }

    @Override
    public void configure(WebSecurity web){
        web.debug(true);
    }
}
