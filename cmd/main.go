package main

import "github.com/digitalcircle-com-br/authapi/lib"

func main() {
	err := lib.Run()
	if err != nil {
		panic(err)
	}
}
