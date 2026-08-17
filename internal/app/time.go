package app

import "time"

var now = time.Now

func sessionDuration(hours int) time.Duration {
	return time.Duration(hours) * time.Hour
}
