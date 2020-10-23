package com.friendship41.authserver.config

import com.friendship41.authserver.service.DefaultMemberUserDetailService
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.context.annotation.Bean
import org.springframework.security.authentication.AuthenticationManager
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter

@EnableWebSecurity
class WebSecurityConfiguration(
        @Autowired private val defaultMemberUserDetailService: DefaultMemberUserDetailService
): WebSecurityConfigurerAdapter() {

    override fun configure(http: HttpSecurity) {
        http
                .httpBasic()
                .and()
                .authorizeRequests()
                .antMatchers("/oauth/token")
                .permitAll()
                .and()
                .csrf()
                .disable()
    }

    override fun configure(auth: AuthenticationManagerBuilder) {
        auth.userDetailsService(this.defaultMemberUserDetailService)
    }

    @Bean
    override fun authenticationManagerBean(): AuthenticationManager {
        return super.authenticationManagerBean()
    }
}
