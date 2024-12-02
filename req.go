package main

import "net/http"

func main() {
	resp, err := http.Get("https://google.es")
	if err != nil {
		panic(err)
	}
	resp.Body.Close()
}
