package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"
)

const Version = "1.1.0"

var logFile *os.File

func getLogPath() string {
	// Get user directory
	var homeDir string

	// Check SUDO_USER environment variable
	if sudoUser := os.Getenv("SUDO_USER"); sudoUser != "" {
		homeDir = filepath.Join("/Users", sudoUser)
		log.Printf("Using SUDO_USER directory: %s", homeDir)
	} else {
		// Check regular HOME environment variable excluding root
		if home := os.Getenv("HOME"); home != "" && home != "/var/root" {
			homeDir = home
			log.Printf("Using HOME directory: %s", homeDir)
		} else {
			// Get from system user information
			if currentUser, err := user.Current(); err == nil && currentUser.HomeDir != "/var/root" {
				homeDir = currentUser.HomeDir
				log.Printf("Using current user directory: %s", homeDir)
			} else {
				// Look for user directories under /Users excluding shared folders
				if userDirs, err := os.ReadDir("/Users"); err == nil {
					for _, dir := range userDirs {
						if dir.IsDir() && dir.Name() != "Shared" && dir.Name() != ".localized" {
							homeDir = filepath.Join("/Users", dir.Name())
							log.Printf("Using detected user directory: %s", homeDir)
							break
						}
					}
				}

				// Fallback to temporary directory
				if homeDir == "" {
					log.Printf("Warning: Unable to determine user home directory, using /tmp")
					return filepath.Join("/tmp", "party.mihomo.helper.log")
				}
			}
		}
	}

	// Log directory
	logDir := filepath.Join(homeDir, "Library", "Application Support", "mihomo-party", "logs")
	return filepath.Join(logDir, "party.mihomo.helper.log")
}

func init() {
	// Get log file path
	logPath := getLogPath()
	logDir := filepath.Dir(logPath)

	// Ensure log directory exists
	if err := os.MkdirAll(logDir, 0755); err != nil {
		// If unable to create specified directory, use temporary directory
		logPath = filepath.Join("/tmp", "party.mihomo.helper.log")
	}

	// Create log file
	f, err := os.OpenFile(logPath, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0644)
	if err != nil {
		log.Fatalf("error opening log file %s: %v", logPath, err)
	}

	logFile = f

	// Multi-writer output
	multiWriter := io.MultiWriter(f, os.Stdout)
	log.SetOutput(multiWriter)

	// Gin log output to stdout
	gin.DefaultWriter = os.Stdout
	gin.DefaultErrorWriter = os.Stderr

	log.Printf("Log file initialized at: %s", logPath)
}

type Server struct {
	engine   *gin.Engine
	addr     string
	srv      *http.Server
	listener net.Listener
}

type Pac struct {
	URL string `json:"url"`
}

type Global struct {
	HOST   string `json:"host"`
	PORT   string `json:"port"`
	BYPASS string `json:"bypass"`
}

type DNS struct {
	Service string `json:"service"`
	DNS     string `json:"dns"`
}

// Validate PAC URL
func validatePacURL(urlStr string) (string, error) {
	if strings.ContainsAny(urlStr, "&|;`$(){}[]<>\\") {
		return "", errors.New("url contains illegal characters")
	}

	u, err := url.Parse(urlStr)
	if err != nil {
		return "", err
	}

	if u.Scheme != "http" && u.Scheme != "https" {
		return "", errors.New("url must use http or https protocol")
	}

	return urlStr, nil
}

// Validate global proxy parameters
func validateGlobalProxy(host, port, bypass string) error {
	if strings.ContainsAny(host, "&|;`$(){}[]\\") {
		return errors.New("host contains illegal characters")
	}

	_, err := strconv.Atoi(port)
	if err != nil {
		return errors.New("port must be numeric")
	}

	// Comma-separated and space-separated bypass domain lists
	var domains []string
	if strings.Contains(bypass, ",") {
		domains = strings.Split(bypass, ",")
	} else {
		domains = strings.Split(bypass, " ")
	}

	for _, domain := range domains {
		domain = strings.TrimSpace(domain)
		if domain == "" {
			continue
		}
		// Allow <local> format, and wildcard *
		if strings.ContainsAny(domain, "&|;`$(){}[]\\") {
			// Whether special format like <local>
			if !(strings.HasPrefix(domain, "<") && strings.HasSuffix(domain, ">")) {
				return errors.New("bypass domain contains illegal characters")
			}
		}
	}

	return nil
}

// Get network service list
func getNetworkServices() ([]string, error) {
	cmd := exec.Command("networksetup", "-listnetworkserviceorder")
	output, err := cmd.Output()
	if err != nil {
		return nil, err
	}

	lines := strings.Split(string(output), "\n")
	var services []string

	for _, line := range lines {

		// Skip hardware port lines like "(Hardware Port: ..., Device: ...)"
		if strings.HasPrefix(line, "(") && strings.Contains(line, ")") && !strings.Contains(line, "Hardware Port:") {

			parts := strings.SplitN(line, ") ", 2)
			if len(parts) == 2 {
				service := strings.TrimSpace(parts[1])
				if service != "" && service != "*" {

					service = strings.TrimPrefix(service, "*")
					service = strings.TrimSpace(service)
					services = append(services, service)
					log.Printf("Found network service: %s", service)
				}
			}
		}
	}

	if len(services) == 0 {
		return nil, errors.New("no network services found")
	}

	log.Printf("Total network services found: %d", len(services))
	return services, nil
}

// Turn off all proxies for a service
func turnOffProxies(service string) error {
	commands := [][]string{
		{"networksetup", "-setautoproxystate", service, "off"},
		{"networksetup", "-setproxyautodiscovery", service, "off"},
		{"networksetup", "-setwebproxystate", service, "off"},
		{"networksetup", "-setsecurewebproxystate", service, "off"},
		{"networksetup", "-setsocksfirewallproxystate", service, "off"},
	}

	for _, args := range commands {
		cmd := exec.Command(args[0], args[1:]...)
		if err := cmd.Run(); err != nil {
			return err
		}
	}

	return nil
}

// Set PAC proxy for a service
func setPACProxy(service, pacURL string) error {
	if err := turnOffProxies(service); err != nil {
		return err
	}

	// Set PAC URL
	cmd1 := exec.Command("networksetup", "-setautoproxyurl", service, pacURL)
	if err := cmd1.Run(); err != nil {
		return err
	}

	// Enable PAC
	cmd2 := exec.Command("networksetup", "-setautoproxystate", service, "on")
	if err := cmd2.Run(); err != nil {
		return err
	}

	cmd3 := exec.Command("networksetup", "-setproxyautodiscovery", service, "on")
	if err := cmd3.Run(); err != nil {
		return err
	}

	return nil
}

// Set global proxy for a service
func setGlobalProxy(service, host, port, bypass string) error {
	if err := turnOffProxies(service); err != nil {
		return err
	}

	commands := [][]string{
		{"networksetup", "-setwebproxy", service, host, port},
		{"networksetup", "-setsecurewebproxy", service, host, port},
		{"networksetup", "-setsocksfirewallproxy", service, host, port},
	}

	for _, args := range commands {
		cmd := exec.Command(args[0], args[1:]...)
		if err := cmd.Run(); err != nil {
			return err
		}
	}

	// Set bypass domains if provided
	if bypass != "" {
		// Split bypass domains using the same logic as validation
		var domains []string
		if strings.Contains(bypass, ",") {
			domains = strings.Split(bypass, ",")
		} else {
			domains = strings.Split(bypass, " ")
		}

		// prepare arguments
		var cleanDomains []string
		for _, domain := range domains {
			domain = strings.TrimSpace(domain)
			if domain != "" {
				cleanDomains = append(cleanDomains, domain)
			}
		}

		if len(cleanDomains) > 0 {
			args := []string{"-setproxybypassdomains", service}
			args = append(args, cleanDomains...)
			cmd := exec.Command("networksetup", args...)
			if err := cmd.Run(); err != nil {
				return err
			}
		}
	}

	return nil
}

// Validate DNS parameters
func validateDNS(service, dns string) error {
	if service == "" {
		return errors.New("service name is required")
	}
	if strings.ContainsAny(service, "&|;`$(){}[]\\") {
		return errors.New("service name contains illegal characters")
	}
	if dns == "" {
		return errors.New("dns is required")
	}
	// dns can be "Empty" or space-separated IP addresses
	if dns != "Empty" {
		for _, ip := range strings.Fields(dns) {
			if strings.ContainsAny(ip, "&|;`$(){}[]\\") {
				return errors.New("dns contains illegal characters")
			}
		}
	}
	return nil
}

// Set DNS for a service
func setDNS(service, dns string) error {
	var args []string
	if dns == "Empty" {
		args = []string{"-setdnsservers", service, "Empty"}
	} else {
		args = append([]string{"-setdnsservers", service}, strings.Fields(dns)...)
	}
	cmd := exec.Command("networksetup", args...)
	return cmd.Run()
}

func NewServer(addr string) *Server {
	engine := gin.Default()
	srv := &http.Server{
		Handler: engine,
	}

	return &Server{
		engine: engine,
		addr:   addr,
		srv:    srv,
	}
}

func (s *Server) setupRoutes() {
	// Add logging for all routes
	log.Printf("Setting up routes for server")

	s.engine.POST("/pac", func(c *gin.Context) {
		log.Printf("Received PAC proxy request with URL: %s", c.Request.URL)
		var pac Pac

		if err := c.ShouldBindJSON(&pac); err != nil {
			log.Printf("Failed to parse PAC request: %v", err)
			c.JSON(http.StatusBadRequest, gin.H{
				"error": err.Error(),
			})
			return
		}

		// Log received PAC URL
		log.Printf("Received PAC URL: %s", pac.URL)

		// Validate PAC URL
		validURL, err := validatePacURL(pac.URL)
		if err != nil {
			log.Printf("PAC URL validation failed: %v", err)
			c.JSON(http.StatusBadRequest, gin.H{
				"error": err.Error(),
			})
			return
		}

		// Get all network services
		log.Printf("Getting network services")
		services, err := getNetworkServices()
		if err != nil {
			log.Printf("Failed to get network services: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "Failed to get network services: " + err.Error(),
			})
			return
		}

		// Log available network services
		log.Printf("Available network services: %v", services)

		// Set PAC proxy for each service
		var errorMessages []string
		var successCount int
		for _, service := range services {
			log.Printf("Setting PAC proxy for service: %s", service)
			if err := setPACProxy(service, validURL); err != nil {
				log.Printf("Failed to set PAC proxy for %s: %v", service, err)
				errorMessages = append(errorMessages, "Failed to set PAC proxy for "+service+": "+err.Error())
			} else {
				log.Printf("Successfully set PAC proxy for %s to %s", service, validURL)
				successCount++
			}
		}

		if successCount > 0 {
			if len(errorMessages) > 0 {
				log.Printf("Encountered some errors setting PAC proxy: %v", errorMessages)
				c.String(200, fmt.Sprintf("PAC proxy set for %d/%d services. Some errors occurred: %s",
					successCount, len(services), strings.Join(errorMessages, "; ")))
			} else {
				log.Printf("Successfully set PAC proxy for all services")
				c.String(200, "PAC proxy has been set for all services")
			}
		} else {
			log.Printf("Failed to set PAC proxy for any service: %v", errorMessages)
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "Failed to set PAC proxy for any service: " + strings.Join(errorMessages, "; "),
			})
		}
	})

	s.engine.POST("/global", func(c *gin.Context) {
		log.Printf("Received global proxy request with URL: %s", c.Request.URL)
		var global Global

		if err := c.ShouldBindJSON(&global); err != nil {
			log.Printf("Failed to parse global proxy request: %v", err)
			c.JSON(http.StatusBadRequest, gin.H{
				"error": err.Error(),
			})
			return
		}

		// Validate global proxy parameters
		if err := validateGlobalProxy(global.HOST, global.PORT, global.BYPASS); err != nil {
			log.Printf("Global proxy validation failed: %v", err)
			c.JSON(http.StatusBadRequest, gin.H{
				"error": err.Error(),
			})
			return
		}

		log.Printf("Received global proxy settings: %v", global)
		services, err := getNetworkServices()
		if err != nil {
			log.Printf("Failed to get network services for global proxy: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "Failed to get network services: " + err.Error(),
			})
			return
		}

		// Process global proxy settings
		var errorMessages []string
		var successCount int
		for _, service := range services {
			log.Printf("Setting global proxy for service: %s", service)
			if err := setGlobalProxy(service, global.HOST, global.PORT, global.BYPASS); err != nil {
				log.Printf("Failed to set global proxy for %s: %v", service, err)
				errorMessages = append(errorMessages, "Failed to set global proxy for "+service+": "+err.Error())
			} else {
				log.Printf("Successfully set global proxy for %s", service)
				successCount++
			}
		}

		if successCount > 0 {
			if len(errorMessages) > 0 {
				log.Printf("Encountered some errors setting global proxy: %v", errorMessages)
				c.String(200, fmt.Sprintf("Global proxy set for %d/%d services. Some errors occurred: %s",
					successCount, len(services), strings.Join(errorMessages, "; ")))
			} else {
				log.Printf("Successfully set global proxy for all services")
				c.String(200, "Global proxy has been set for all services")
			}
		} else {
			log.Printf("Failed to set global proxy for any service: %v", errorMessages)
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "Failed to set global proxy for any service: " + strings.Join(errorMessages, "; "),
			})
		}
	})

	s.engine.POST("/dns", func(c *gin.Context) {
		log.Printf("Received DNS set request")
		var dns DNS

		if err := c.ShouldBindJSON(&dns); err != nil {
			log.Printf("Failed to parse DNS request: %v", err)
			c.JSON(http.StatusBadRequest, gin.H{
				"error": err.Error(),
			})
			return
		}

		log.Printf("Received DNS settings: service=%s, dns=%s", dns.Service, dns.DNS)

		if err := validateDNS(dns.Service, dns.DNS); err != nil {
			log.Printf("DNS validation failed: %v", err)
			c.JSON(http.StatusBadRequest, gin.H{
				"error": err.Error(),
			})
			return
		}

		if err := setDNS(dns.Service, dns.DNS); err != nil {
			log.Printf("Failed to set DNS for %s: %v", dns.Service, err)
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "Failed to set DNS: " + err.Error(),
			})
			return
		}

		log.Printf("Successfully set DNS for %s to %s", dns.Service, dns.DNS)
		c.String(200, "DNS has been set successfully")
	})

	s.engine.GET("/off", func(c *gin.Context) {
		log.Printf("Received request to turn off proxy")
		services, err := getNetworkServices()
		if err != nil {
			log.Printf("Failed to get network services for turning off proxy: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "Failed to get network services: " + err.Error(),
			})
			return
		}

		// Turn off proxy for each service
		var errorMessages []string
		var successCount int
		for _, service := range services {
			log.Printf("Turning off proxy for service: %s", service)
			if err := turnOffProxies(service); err != nil {
				log.Printf("Failed to turn off proxy for %s: %v", service, err)
				errorMessages = append(errorMessages, "Failed to turn off proxy for "+service+": "+err.Error())
			} else {
				log.Printf("Successfully turned off proxy for %s", service)
				successCount++
			}
		}

		// If at least one service succeeded, consider it a partial success
		if successCount > 0 {
			if len(errorMessages) > 0 {
				log.Printf("Encountered some errors turning off proxy: %v", errorMessages)
				c.String(200, fmt.Sprintf("Proxy turned off for %d/%d services. Some errors occurred: %s",
					successCount, len(services), strings.Join(errorMessages, "; ")))
			} else {
				log.Printf("Successfully turned off proxy for all services")
				c.String(200, "Proxy has been turned off for all services")
			}
		} else {
			// Only return error if ALL services failed
			log.Printf("Failed to turn off proxy for any service: %v", errorMessages)
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "Failed to turn off proxy for any service: " + strings.Join(errorMessages, "; "),
			})
		}
	})
}

// Create initial socket
func (s *Server) createSocket() error {
	listener, err := net.Listen("unix", s.addr)
	if err != nil {
		log.Printf("Failed to create initial socket: %v", err)
		return err
	}

	// Store listener reference
	s.listener = listener

	// Set socket permissions
	if err := os.Chmod(s.addr, 0666); err != nil {
		log.Printf("Failed to set socket permissions: %v", err)
		return err
	}

	// Start server in goroutine
	go func() {
		if err := s.srv.Serve(listener); err != nil && err != http.ErrServerClosed {
			log.Printf("Server error: %v\n", err)
		}
	}()

	log.Printf("Socket created successfully")
	return nil
}

func (s *Server) Start() error {
	s.setupRoutes()

	// Remove existing socket file if exists
	if err := os.RemoveAll(s.addr); err != nil {
		log.Printf("Failed to remove existing socket file: %v", err)
		return err
	}

	// Create new socket listener
	if err := s.createSocket(); err != nil {
		return err
	}

	// Start signal handler for socket recreation
	s.startSignalHandler()

	log.Printf("Server started successfully, listening on %s", s.addr)
	return nil
}

// Signal handler to recreate socket on SIGUSR1
func (s *Server) startSignalHandler() {
	go func() {
		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, syscall.SIGUSR1)

		for range sigChan {
			log.Printf("Received SIGUSR1 signal, checking and recreating socket if needed")
			if _, err := os.Stat(s.addr); os.IsNotExist(err) {
				log.Printf("Socket file %s not found, recreating listener", s.addr)
				if err := s.recreateListener(); err != nil {
					log.Printf("Failed to recreate listener: %v", err)
				} else {
					log.Printf("Successfully recreated listener and socket file")
				}
			} else {
				log.Printf("Socket file exists, no need to recreate")
			}
		}
	}()
}

// Recreate the entire listener when socket file is missing
func (s *Server) recreateListener() error {
	log.Printf("Recreating listener for socket %s", s.addr)

	// Store reference to old listener but don't close it immediately
	oldListener := s.listener

	// Remove any existing socket file
	if err := os.RemoveAll(s.addr); err != nil {
		log.Printf("Failed to remove existing socket file: %v", err)
	}

	// Create new listener
	listener, err := net.Listen("unix", s.addr)
	if err != nil {
		log.Printf("Failed to recreate listener: %v", err)
		return err
	}
	log.Printf("New listener created successfully")

	// Set socket permissions
	if err := os.Chmod(s.addr, 0666); err != nil {
		log.Printf("Failed to set socket permissions: %v", err)
		listener.Close()
		return err
	}
	log.Printf("Socket permissions set successfully")

	// Update listener reference before starting server
	s.listener = listener

	// Create a new server instance for the new listener
	newSrv := &http.Server{
		Handler: s.engine,
	}

	// Start new server goroutine
	go func() {
		log.Printf("Starting new server with recreated listener")
		if err := newSrv.Serve(listener); err != nil && err != http.ErrServerClosed {
			log.Printf("Server error after recreation: %v\n", err)
		}
	}()

	// Don't actively close the old listener
	// This prevents the socket file from being deleted
	if oldListener != nil {
		log.Printf("Old listener will exit naturally")
	}

	// Verify socket file exists after a short delay
	time.Sleep(100 * time.Millisecond)
	if _, err := os.Stat(s.addr); err != nil {
		log.Printf("Warning: Socket file verification failed: %v", err)
		return err
	}
	log.Printf("Socket file verified: %s", s.addr)

	return nil
}

func main() {
	log.Printf("Starting mihomo-party-helper server v%s", Version)
	server := NewServer("/tmp/mihomo-party-helper.sock")

	if err := server.Start(); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}

	log.Printf("Server v%s started successfully", Version)
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Use http.Server's Shutdown method
	if err := server.srv.Shutdown(ctx); err != nil {
		log.Fatalf("Server forced to shutdown: %v", err)
	}

	if server.listener != nil {
		server.listener.Close()
	}

	if err := os.RemoveAll(server.addr); err != nil {
		log.Printf("Failed to remove socket file: %v", err)
	}

	if logFile != nil {
		logFile.Close()
	}
	log.Printf("Server shutdown completed")
}
