package com.janlele91.pocCVE202222978;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class MainController {

    @GetMapping("/admin/*")
    public String mainPage() {
        return "This is a CVE-2022-22978 demo";
    }

}
