package com.example.wzappdemo.controller;

import com.example.wzappdemo.task.TokenTask;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.client.RestTemplate;

import javax.annotation.Resource;
import java.util.Map;

/**
 * @Description: TODO 类描述
 * @Author: Ze WANG
 **/
@Controller
public class HelloController {

    @Autowired
    private RestTemplate restTemplate;

    @Autowired
    TokenTask tokenTask;

//    @GetMapping("/index.html")
    public String hello(String code, Model model) {
        if (code != null) {
            MultiValueMap<String, String> map = new LinkedMultiValueMap<>();
            map.add("code", code);
            map.add("client_id", "wz-app");
            map.add("client_secret", "123");
            map.add("redirect_uri", "http://localhost:8083/index.html");
            map.add("grant_type", "authorization_code");
            //获取令牌
            Map<String,String> resp = restTemplate.postForObject("http://localhost:8081/oauth/token", map, Map.class);
            String access_token = resp.get("access_token");

            //请求资源
            System.out.println("令牌： "+access_token);
            HttpHeaders headers = new HttpHeaders();
            headers.add("Authorization", "Bearer " + access_token);
            HttpEntity<Object> httpEntity = new HttpEntity<>(headers);
            ResponseEntity<String> entity = restTemplate.exchange("http://localhost:8082/admin/res", HttpMethod.GET, httpEntity, String.class);
            model.addAttribute("token","令牌："+access_token);
            model.addAttribute("res", "资源"+entity.getBody());
        }
        return "index";
    }


    @GetMapping("/index.html")
    public String res(String code, Model model) {
        System.out.println("code==="+code);
        String data = tokenTask.getData(code);
        model.addAttribute("res", data);
        return "index";
    }
}
