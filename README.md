# 스프링 시큐리티란?

## 시큐리티가 필요한 이유

웹사이트는 각종 서비스를 하기 위한 리소스와 서비스를 사용하는 유저들의 개인 정보를 가지고 있습니다. 이들 리소스를 보호하기 위해서 일반적으로 웹 사이트는 두가지 보안 정책을 설정해야 합니다.

- 서버 리소스
- 유저들의 개인정보

<img src="../images/fig-0-site-securities.png" width="600" style="max-width:600px;width:100%;" />

## 인증 (Authentication)

사이트에 접근하는 사람이 누구인지 시스템이 알아야 합니다. 익명사용자(anonymous user)를 허용하는 경우도 있지만, 특정 리소스에 접근하거나 개인화된 사용성을 보장 받기 위해서는 반드시 로그인하는 과정이 필요합니다. 로그인은 보통 username / password 를 입력하고 로그인하는 경우와 sns 사이트를 통해 인증을 대리하는 경우가 있습니다.

- UsernamePassword 인증
    - Session 관리
    - 토큰 관리 (sessionless)
- Sns 로그인 (소셜 로그인) : 인증 위임

## 인가 혹은 권한(Authorization)

사용자가 누구인지 알았다면 사이트 관리자 혹은 시스템은 로그인한 사용자가 어떤 일을 할 수 있는지 권한을 설정합니다. 권한은 특정 페이지에 접근하거나 특정 리소스에 접근할 수 있는 권한여부를 판단하는데 사용됩니다. 개발자는 권한이 있는 사용자에게만 페이지나 리소스 접근을 허용하도록 코딩해야 하는데, 이런 코드를 쉽게 작성할 수 있도록 프레임워크를 제공하는 것이 스프링 시큐리티 프레임워크(Spring Security Framework) 입니다.

- Secured : deprecated
- PrePostAuthorize
- AOP

## 메모리 사용자 인증

간단히 특정된 소스를 위한 서비스나 테스트를 위해 사용하는 용도로 사용합니다. 스프링 시큐리티를 테스트 하기 위한 용도로 사용합니다.

- 기본 사용자 로그인
- application.yml 에 설정하고 로그인하기
- UserDetailService 를 이용하기
- WebSecurityConfigurerAdapter 를 사용하기

## 실습할 내용

1. basic-test 서버에 기본 사용자(user) 로 로그인한다
2. applicaiton.yml 에 user1 을 만들고 로그인한다.
3. 어플리케이션 객체에 UserDetailsService 빈을 만들어서 로그인을 한다.
4. SecurityConfig 를 만들고 이를 통해 로그인 한다.
5. SecurityMessage (UserDetails, message) 를 통해 /user 페이지와 /admin 페이지 접근 권한을 테스트 한다.
