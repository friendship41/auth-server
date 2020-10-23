package com.friendship41.authserver.testtest

import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RestController

@RestController
class TestController {
    @RequestMapping("/")
    fun testAll():Any {
        return "{\"result\":\"success\"}"
    }
}
