package com.example.neuro_admin;

import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.RestTemplate;
import java.util.Map;

@RestController
@RequestMapping("/api/v1/sentinel")
@CrossOrigin(origins = "*") // Allows your React UI to connect
public class SentinelController {

    @GetMapping("/scan")
    public Map<String, Object> runNeuralScan(@RequestParam(defaultValue = "README.md") String target) {
       String pythonApiUrl = "https://turbo-robot-4rp45r5xprv257j6-8000.app.github.dev/api/scan?target=" + target;
        RestTemplate restTemplate = new RestTemplate();

        // Java "asks" Python to perform the scan
        try {
            return restTemplate.getForObject(pythonApiUrl, Map.class);
        } catch (Exception e) {
            return Map.of("error", "Neural Engine Unreachable", "details", e.getMessage());
        }
    }
}