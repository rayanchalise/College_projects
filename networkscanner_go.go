package main

import (
    "fmt"
    "net"
    "sort"
    "sync"
    "time"
)

func scanPort(protocol, hostname string, port int, wg *sync.WaitGroup, results chan<- int) {
    defer wg.Done()
    address := fmt.Sprintf("%s:%d", hostname, port)
    conn, err := net.DialTimeout(protocol, address, 1*time.Second)
    if err != nil {
        return
    }
    conn.Close()
    results <- port
}

func main() {
    hostname := "www.website.com"
    protocol := "tcp"
    var ports []int
    for i := 1; i <= 1024; i++ {
        ports = append(ports, i)
    }

    var wg sync.WaitGroup
    results := make(chan int, len(ports))
    
    for _, port := range ports {
        wg.Add(1)
        go scanPort(protocol, hostname, port, &wg, results)
    }

    go func() {
        wg.Wait()
        close(results)
    }()

    openPorts := []int{}
    for port := range results {
        openPorts = append(openPorts, port)
    }

    sort.Ints(openPorts)
    for _, port := range openPorts {
        fmt.Printf("Port %d is open\n", port)
    }
}

