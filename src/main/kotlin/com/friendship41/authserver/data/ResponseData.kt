package com.friendship41.authserver.data

data class ResBodyOauthToken(
        var access_token: String,
        var token_type: String,
        var refresh_token: String,
        var expires_in: Long,
        var roles: String
)

data class ResBodyTokenKey(
        var alg: String,
        var value: String
)
