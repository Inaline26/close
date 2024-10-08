package com.closegame.unlucky.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import com.closegame.unlucky.model.Details;

@Repository
public interface DetailsRepository extends JpaRepository<Details, Long> {
}
