package com.oauth.sample;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.oauth2.client.oidc.web.server.logout.OidcClientInitiatedServerLogoutSuccessHandler;
import org.springframework.security.oauth2.client.registration.ReactiveClientRegistrationRepository;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.server.authentication.logout.ServerLogoutSuccessHandler;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class SecurityConfig {
    //@Autowired
    //private ReactiveClientRegistrationRepository clientRegistrationRepository;
    @Bean
    SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
        http.csrf(AbstractHttpConfigurer::disable)
                .authorizeHttpRequests(authorizeHttpRequests ->
                                        authorizeHttpRequests.anyRequest().authenticated())
                //.formLogin(form -> form.defaultSuccessUrl("/hello", true));
                .oauth2Login(oauth2 -> oauth2.defaultSuccessUrl("http://localhost:4200/dashboard", true))
                /*.logout((logout) -> logout
                        .logoutSuccessHandler(oidcLogoutSuccessHandler())
                );*/
                .logout((logout) -> {
                    logout.logoutUrl("/authentication/logout");
                    logout.invalidateHttpSession(true);
                    logout.logoutSuccessUrl("/");
                    logout.clearAuthentication(true);
                    logout.deleteCookies("auth_code", "JSESSIONID", "refreshToken", "Authorization");
                });
        return http.build();
    }

    /*private ServerLogoutSuccessHandler oidcLogoutSuccessHandler() {
        OidcClientInitiatedServerLogoutSuccessHandler oidcLogoutSuccessHandler =
                new OidcClientInitiatedServerLogoutSuccessHandler(this.clientRegistrationRepository);

        // Sets the location that the End-User's User Agent will be redirected to
        // after the logout has been performed at the Provider
        oidcLogoutSuccessHandler.setPostLogoutRedirectUri("{baseUrl}");

        return oidcLogoutSuccessHandler;
    }*/
}
