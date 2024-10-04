package com.closegame.unlucky.service;


import com.closegame.unlucky.model.Demo;

import java.util.List;

public interface DemoService {
    void save(Demo demo);
    List<Demo> findAll();
    Demo findById(long id);
}

