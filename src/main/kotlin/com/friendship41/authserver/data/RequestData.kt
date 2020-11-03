package com.friendship41.authserver.data

data class ReqBodyOauthToken(
        var grantType: String?,
        var username: String,
        var password: String,
        var scope: String?,
        var checkedClientDetails: OauthClientDetails
)
