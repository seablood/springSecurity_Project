package com.example.springSecurity.config;

import com.example.springSecurity.config.auth.PrincipalDetailsService;
import com.example.springSecurity.config.jwt.JwtTokenProvider;
import com.example.springSecurity.config.jwt.TokenFilter;
import com.example.springSecurity.config.login.filter.CustomJsonUsernamePasswordAuthenticationFilter;
import com.example.springSecurity.config.login.handler.LoginFailureHandler;
import com.example.springSecurity.config.login.handler.LoginSuccessHandler;
import com.example.springSecurity.config.oauth2.OAuth2UserCustomService;
import com.example.springSecurity.config.oauth2.handler.OAuth2FailureHandler;
import com.example.springSecurity.config.oauth2.handler.OAuth2SuccessHandler;
import com.example.springSecurity.repository.UserRepository;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.logout.LogoutFilter;

import static org.springframework.boot.autoconfigure.security.servlet.PathRequest.toH2Console;

@Configuration
@RequiredArgsConstructor
@EnableMethodSecurity(securedEnabled = true)
public class SecurityConfig {
    private final OAuth2SuccessHandler oAuth2SuccessHandler;
    private final OAuth2FailureHandler oAuth2FailureHandler;
    private final OAuth2UserCustomService oAuth2UserCustomService;
    private final BCryptPasswordEncoder bCryptPasswordEncoder;
    private final PrincipalDetailsService principalDetailsService;
    private final JwtTokenProvider jwtTokenProvider;
    private final UserRepository userRepository;
    private final ObjectMapper objectMapper;

    @Bean
    public WebSecurityCustomizer configure() {
        return (web) -> web.ignoring()
                .requestMatchers(toH2Console())
                .requestMatchers("/v2/api-docs", "/swagger-resources/**",
                        "/swagger-ui.html", "/webjars/**", "/swagger/**", "/sign-api/exception",
                        "/static/**", "/favicon.ico");
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception{
        /*http.csrf((csrf) -> csrf.disable());
        http.authorizeHttpRequests((authorizeRequests) ->
                    authorizeRequests
                            .requestMatchers("/user/**").authenticated()
                            .requestMatchers("/manager/**").hasAnyRole("ADMIN", "MANAGER")
                            .requestMatchers("/admin/**").hasRole("ADMIN")
                            .anyRequest().permitAll()); // 인증 처리

        http.formLogin((formLogin) -> formLogin
                .loginPage("/loginForm")
                        .loginProcessingUrl("/login") // 폼 로그인 기본 로그인 POST 요청 URL
                        .defaultSuccessUrl("/"));

        http.oauth2Login((oauth2) -> oauth2
                .loginPage("/loginForm"));

        return http.build();*/

        http.formLogin((formLogin) -> formLogin.disable());
        http.httpBasic((httpBasic) -> httpBasic.disable());
        http.csrf((csrf) -> csrf.disable());
        http.headers((headers) -> headers.frameOptions((frameOptions) -> frameOptions.disable()));
        http.sessionManagement((session) -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS));

        http.authorizeHttpRequests((authorizeRequests) ->
                authorizeRequests
                        .requestMatchers("/user/**", "/jwt-test").authenticated()
                        .requestMatchers("/manager/**").hasAnyRole("ADMIN", "MANAGER")
                        .requestMatchers("/admin/**").hasRole("ADMIN")
                        .anyRequest().permitAll());

        http.oauth2Login((oauth2Login) ->
                oauth2Login
                        .loginPage("/loginForm")
                        .successHandler(oAuth2SuccessHandler)
                        .failureHandler(oAuth2FailureHandler)
                        .userInfoEndpoint((endpoint) -> endpoint.userService(oAuth2UserCustomService)));

        http.addFilterAfter(customJsonUsernamePasswordAuthenticationFilter(), LogoutFilter.class);
        http.addFilterBefore(tokenFilter(), CustomJsonUsernamePasswordAuthenticationFilter.class);

        return http.build();
    }

    @Bean
    public AuthenticationManager authenticationManager(){
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
        provider.setPasswordEncoder(bCryptPasswordEncoder);
        provider.setUserDetailsService(principalDetailsService);
        return new ProviderManager(provider);
    }

    @Bean
    public LoginSuccessHandler loginSuccessHandler() {
        return new LoginSuccessHandler(jwtTokenProvider, userRepository);
    }

    @Bean
    public LoginFailureHandler loginFailureHandler() {
        return new LoginFailureHandler();
    }

    @Bean
    public CustomJsonUsernamePasswordAuthenticationFilter customJsonUsernamePasswordAuthenticationFilter(){
        CustomJsonUsernamePasswordAuthenticationFilter filter = new CustomJsonUsernamePasswordAuthenticationFilter(objectMapper);
        filter.setAuthenticationManager(authenticationManager());
        filter.setAuthenticationSuccessHandler(loginSuccessHandler());
        filter.setAuthenticationFailureHandler(loginFailureHandler());

        return filter;
    }

    @Bean
    public TokenFilter tokenFilter() {
        return new TokenFilter(jwtTokenProvider, userRepository, principalDetailsService);
    }
}
