package com.example.userserver.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;


/**
 * @Description: 测试接口
 * @Author: Ze WANG
 **/
@RestController
public class ResController {

    @GetMapping("/res")
    public String hello() {
        return "====普通资源====";
    }
    @GetMapping("/admin/res")
    public String admin() {
        return "====admin资源====";
    }

}
