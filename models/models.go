package models

import (
	"errors"
	"time"
)

var ErrNoRecord = errors.New("models: no matching record found")

// Database
type User struct {
        gorm.Model
        Username string `gorm:"unique_index;not null"`
        Email    string `gorm:"unique_index;not null"`
        Password string `gorm:"not null"`
}



