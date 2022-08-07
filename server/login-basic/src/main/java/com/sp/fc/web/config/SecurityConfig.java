package com.sp.fc.web.config;

import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.security.access.hierarchicalroles.RoleHierarchy;
import org.springframework.security.access.hierarchicalroles.RoleHierarchyImpl;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;

@EnableWebSecurity(debug = true)
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    private final CustomAuthDetails customAuthDetails;

    public SecurityConfig(CustomAuthDetails customAuthDetails) {
        this.customAuthDetails = customAuthDetails;
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        //withDefaultPasswordEncoder 는 자동적으로 pw를 encode 해주는
        //static 메소드이다. 그러나 위험해서 사용하지 않는걸 권장하지만 테스트시에는 사용하도록 한다.
        auth.inMemoryAuthentication()
                .withUser(User.withDefaultPasswordEncoder()
                        .username("user2")
                        .password("2222")
                        .roles("USER"))
                .withUser(User.withDefaultPasswordEncoder()
                        .username("admin")
                        .password("3333")
                        .roles("ADMIN"))
        ;
    }

    @Bean
    RoleHierarchy roleHierarchy() {
        //보통 관리자는 유저가 접근할 수 있는 페이지에 모두 접근 가능하기 때문에
        //해당 설정을 통해 관리자는 유저 페이지에 접근 할 수 있다.
        RoleHierarchyImpl roleHierarchy = new RoleHierarchyImpl();
        roleHierarchy.setHierarchy("ROLE_ADMIN > ROLE_USER");

        return roleHierarchy;
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .authorizeRequests(request->{
                    request
                            .antMatchers("/").permitAll()
                            .anyRequest().authenticated()
                    ;
                })
                .formLogin(
                        login -> login.loginPage("/login")
                                .permitAll()
                                //alwaysUse 를 True 설정 시 로그인하면 무조건 메인페이지로 가기 때문에
                                //false 로 설정하는 것이 좋다.
                                .defaultSuccessUrl("/", false)
                                .failureUrl("/login-error")
                                .authenticationDetailsSource(customAuthDetails)
                )
                .logout(
                        logout -> logout.logoutSuccessUrl("/")
                )
                .exceptionHandling(exception -> exception.accessDeniedPage("/access-denied"))
                ;
    }

    @Override
    public void configure(WebSecurity web) throws Exception {
        //현재 메인페이지를 제외한 모든 페이지에 대해 권한 인증을 적용시켜놨기 때문에
        //css,js도 같이 권한이 걸려 적용이 안되는 문제가 있다.
        //따라서 해당 web resource는 적용이 안되도록 따로 설정을 해둬야 한다.
        web.ignoring()
                .requestMatchers(
                        PathRequest.toStaticResources().atCommonLocations()
                );
    }
}
