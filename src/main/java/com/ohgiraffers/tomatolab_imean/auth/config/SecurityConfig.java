package com.ohgiraffers.tomatolab_imean.auth.config;


import com.ohgiraffers.tomatolab_imean.auth.config.handler.AuthFailHandler;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.web.filter.HiddenHttpMethodFilter;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    private final AuthFailHandler authFailHandler;

    @Autowired
    public SecurityConfig(AuthFailHandler authFailHandler) {
        this.authFailHandler = authFailHandler;
    }

    @Bean
    public HiddenHttpMethodFilter hiddenHttpMethodFilter() {
        return new HiddenHttpMethodFilter();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public WebSecurityCustomizer webSecurityCustomizer() {
        return web -> web.ignoring()
                .requestMatchers(PathRequest.toStaticResources().atCommonLocations())
                .requestMatchers("/css/**", "/common.css", "/js/**", "/images/**", "/fonts/**", "/webjars/**");
    }

    @Bean
    public SecurityFilterChain config(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(auth -> {
            // 모든 사용자가 접근 가능한 경로
            auth.requestMatchers("/auth/**", "/members/signup", "/", "/couple/register").permitAll();
            
            // 로그인한 사용자만 접근 가능한 경로
            auth.requestMatchers("/members/**", "/couple/**").authenticated();
            
            // 기타 모든 요청은 인증 필요
            auth.anyRequest().authenticated();
        }).formLogin(login -> {
            login.loginPage("/auth/login");
            login.usernameParameter("username"); // HTML 폼 필드 이름
            login.passwordParameter("password"); // HTML 폼 필드 이름
            login.defaultSuccessUrl("/", true);
            login.failureHandler(authFailHandler);
        }).logout(logout -> {
            logout.logoutRequestMatcher(new AntPathRequestMatcher("/logout"));
            logout.deleteCookies("JSESSIONID");
            logout.invalidateHttpSession(true);
            logout.logoutSuccessUrl("/");
        }).sessionManagement(session -> {
            session.maximumSessions(1);
            session.invalidSessionUrl("/");
        }).csrf(csrf -> csrf.disable());

        return http.build();
    }
}