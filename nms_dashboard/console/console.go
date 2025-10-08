package console

import (
    "bufio"
    "bytes"
    "encoding/json"
    "fmt"
    "net/http"
    "os"
    "strings"
)

type Device struct {
    IP   string
    Port string
    Name string
}

func fetchDevices(subnet, port string) ([]Device, error) {
    url := fmt.Sprintf("http://localhost:8080/discover_agents?subnet=%s&port=%s", subnet, port)

    resp, err := http.Get(url)
    if err != nil {
        return nil, err
    }
    defer resp.Body.Close()

    var result struct {
        Devices []struct {
            IP   string `json:"ip"`
            Port string `json:"port"`
            Data struct {
                Hostname string `json:"hostname"`
            } `json:"data"`
        } `json:"devices"`
    }

    if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
        return nil, err
    }

    devices := make([]Device, 0, len(result.Devices))
    for _, d := range result.Devices {
        name := d.Data.Hostname
        if name == "" {
            name = d.IP
        }
        devices = append(devices, Device{IP: d.IP, Port: port, Name: name})
    }

    return devices, nil
}

func SelectDevice(devices []Device) *Device {
    devices, err := fetchDevices("192.168.2.0/24", "8080")
    if err != nil {
        fmt.Println("Error fetching devices:", err)
        return nil
    }

    if len(devices) == 0 {
        fmt.Println("No devices found.")
        return nil
    }

    fmt.Println("Select device to open console:")
    for i, d := range devices {
        fmt.Printf("[%d] %s (%s:%s)\n", i+1, d.Name, d.IP, d.Port)
    }

    var choice int
    fmt.Print("Enter choice number: ")
    _, err = fmt.Scanf("%d\n", &choice)
    if err != nil || choice < 1 || choice > len(devices) {
        fmt.Println("Invalid choice")
        return nil
    }
    return &devices[choice-1]
}

func ConsoleSession(device *Device) {
    reader := bufio.NewReader(os.Stdin)
    fmt.Printf("Connected to %s console. Type 'exit' to quit.\n", device.Name)

    for {
        fmt.Printf("%s> ", device.Name)
        cmd, err := reader.ReadString('\n')
        if err != nil {
            fmt.Println("Error reading input:", err)
            return
        }
        cmd = strings.TrimSpace(cmd)
        if cmd == "exit" {
            fmt.Println("Exiting console session.")
            break
        }
        output, err := sendCommand(device, cmd)
        if err != nil {
            fmt.Println("Error:", err)
            continue
        }
        fmt.Println(output)
    }
}

func sendCommand(device *Device, command string) (string, error) {
    url := fmt.Sprintf("http://%s:%s/console", device.IP, device.Port)
    payload := map[string]string{"command": command}
    b, _ := json.Marshal(payload)

    resp, err := http.Post(url, "application/json", bytes.NewBuffer(b))
    if err != nil {
        return "", err
    }
    defer resp.Body.Close()

    var respData struct {
        Output string `json:"output"`
        Error  string `json:"error"`
    }
    err = json.NewDecoder(resp.Body).Decode(&respData)
    if err != nil {
        return "", err
    }
    if respData.Error != "" {
        return "", fmt.Errorf(respData.Error)
    }
    return respData.Output, nil
}
