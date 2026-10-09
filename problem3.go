package main

import (
	"fmt"
	"sync"
)

func main() {
	cnp := make(chan func(), 10)

	var wg sync.WaitGroup

	wg.Add(1)

	for i := 0; i < 4; i++ {
		go func() {
			for f := range cnp {
				f()
				wg.Done()
			}
		}()
	}

	cnp <- func() {
		fmt.Println("HERE1")
	}

	wg.Wait()

	fmt.Println("Hello")
}
