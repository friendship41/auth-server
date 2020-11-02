package com.friendship41.authserver.router

import com.friendship41.authserver.handler.TokenHandler
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.web.reactive.function.server.RequestPredicate
import org.springframework.web.reactive.function.server.RequestPredicates
import org.springframework.web.reactive.function.server.RouterFunctions
import org.springframework.web.reactive.function.server.router

@Configuration
class TokenRouter(private val tokenHandler: TokenHandler) {
    @Bean
    fun memberRouterFunction() = RouterFunctions.nest(
            RequestPredicates.path("/oauth"),
            router {
                listOf(
                        POST("token", tokenHandler::handlePostTokenRequest)
                )})

    @Bean
    fun testRouterFunction() = RouterFunctions.nest(
            RequestPredicates.path("/"),
            router {
                listOf(
                        GET("qwe", tokenHandler::testReq)
                )
            }
    )

}
