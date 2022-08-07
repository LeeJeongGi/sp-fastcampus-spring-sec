package com.sp.fc.web.config;

import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

@EnableWebSecurity(debug = true)
@EnableGlobalMethodSecurity(prePostEnabled = true) //이제부터 권한을 체크하겠다는 표시
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        //사용자를 임의로 등록하는 방법
        //설정을 통해 사용자를 등록하게 된다면 .yml 파일에 등록된 사용자 user1은 사용할 수가 없다.
        auth.inMemoryAuthentication()
                .withUser(User.builder()
                        .username("user2")
                        .password(passwordEncoder().encode("2222"))
                        .roles("USER"))
                .withUser(User.builder()
                        .username("admin")
                        .password(passwordEncoder().encode("3333"))
                        .roles("ADMIN"))
        ;
    }

    @Bean
    PasswordEncoder passwordEncoder() {
        //패스워드를 2222 이런식으로 설정하면 인코딩 설정이 안되어 있어 오류가 난다.
        //따라서 인코딩을 추가해줘야한다.
        return new BCryptPasswordEncoder();
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        //기본적으로 스프링 시큐리티 config 설정은 모든 요청에 대해서 검증을 해라 라고 설정이 되어 있다.
        //따라서 메소드를 재정의해서 내 어떤 요청은 제외할 수 있도록 설정 가능
        http.authorizeRequests(
                (requests) ->
                        requests.antMatchers("/").permitAll()
                                .anyRequest().authenticated()
        );
        http.formLogin();
        http.httpBasic();
    }
}