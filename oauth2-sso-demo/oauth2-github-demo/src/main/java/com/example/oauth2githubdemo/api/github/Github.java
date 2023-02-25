package com.example.oauth2githubdemo.api.github;


import com.example.oauth2githubdemo.api.ApiBinding;

/**
 * @Description: Github请求
 * @Author: Ze WANG
 **/
public class Github extends ApiBinding {
    private static final String BASE_URL = "https://api.github.com";

    public Github(String accessToken) {
        super(accessToken);
    }
    public String getProfile() {
        return restTemplate.getForObject(BASE_URL + "/user", String.class);
    }
}
