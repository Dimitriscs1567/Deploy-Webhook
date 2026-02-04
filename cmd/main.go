package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type Config struct {
	Port       string               `json:"port"`
	Secret     string               `json:"secret"`
	ScriptsDir string               `json:"scripts_dir"`
	Apps       map[string]AppConfig `json:"apps"`
}

type AppConfig struct {
	Script string `json:"script"`
	Branch string `json:"branch"`
}

type GitHubPushEvent struct {
	Ref        string `json:"ref"`
	Repository struct {
		Name     string `json:"name"`
		FullName string `json:"full_name"`
	} `json:"repository"`
}

var (
	config     Config
	deployLock sync.Mutex
	logger     *log.Logger
)

func main() {
	logger = log.New(os.Stdout, "[deployer] ", log.LstdFlags)

	exePath, err := os.Executable()
	if err != nil {
		logger.Fatalf("Failed to get executable path: %v", err)
	}
	baseDir := filepath.Dir(exePath)

	configPath := filepath.Join(baseDir, "config.json")
	if err := loadConfig(configPath, baseDir); err != nil {
		logger.Fatalf("Failed to load config: %v", err)
	}

	http.HandleFunc("/gogetit", webhookHandler)
	http.HandleFunc("/health", healthHandler)

	addr := ":" + config.Port
	logger.Printf("Starting webhook server on %s", addr)
	logger.Fatal(http.ListenAndServe(addr, nil))
}

func loadConfig(path, baseDir string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	if err := json.NewDecoder(f).Decode(&config); err != nil {
		return err
	}
	if config.ScriptsDir == "" {
		config.ScriptsDir = filepath.Join(baseDir, "scripts")
	} else if !filepath.IsAbs(config.ScriptsDir) {
		config.ScriptsDir = filepath.Join(baseDir, config.ScriptsDir)
	}
	logger.Printf("Scripts directory: %s", config.ScriptsDir)
	return nil
}

func healthHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("OK"))
}

func webhookHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		logger.Printf("Error reading body: %v", err)
		http.Error(w, "Failed to read body", http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	if config.Secret != "" {
		sig := r.Header.Get("X-Hub-Signature-256")
		if !verifySignature(body, sig, config.Secret) {
			logger.Printf("Invalid signature from %s", r.RemoteAddr)
			http.Error(w, "Invalid signature", http.StatusUnauthorized)
			return
		}
	}

	event := r.Header.Get("X-GitHub-Event")
	if event != "push" {
		logger.Printf("Ignoring event: %s", event)
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Event ignored"))
		return
	}

	var payload GitHubPushEvent
	if err := json.Unmarshal(body, &payload); err != nil {
		logger.Printf("Error parsing payload: %v", err)
		http.Error(w, "Invalid payload", http.StatusBadRequest)
		return
	}

	repoName := payload.Repository.Name
	branch := strings.TrimPrefix(payload.Ref, "refs/heads/")

	logger.Printf("Received push for %s on branch %s", repoName, branch)

	appConfig, exists := config.Apps[repoName]
	if !exists {
		logger.Printf("No config for repo: %s", repoName)
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Repo not configured"))
		return
	}

	targetBranch := appConfig.Branch
	if targetBranch == "" {
		targetBranch = "prod"
	}

	if branch != targetBranch {
		logger.Printf("Ignoring branch %s (waiting for %s)", branch, targetBranch)
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Branch ignored"))
		return
	}

	go runDeploy(repoName, appConfig.Script)

	w.WriteHeader(http.StatusAccepted)
	w.Write([]byte("Deployment started"))
}

func verifySignature(payload []byte, sig, secret string) bool {
	if !strings.HasPrefix(sig, "sha256=") {
		return false
	}
	sig = strings.TrimPrefix(sig, "sha256=")

	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(payload)
	expected := hex.EncodeToString(mac.Sum(nil))

	return hmac.Equal([]byte(expected), []byte(sig))
}

func runDeploy(repoName, script string) {
	deployLock.Lock()
	defer deployLock.Unlock()

	scriptPath := filepath.Join(config.ScriptsDir, script)
	logger.Printf("Running deploy script for %s: %s", repoName, scriptPath)

	start := time.Now()
	cmd := exec.Command("/bin/bash", scriptPath)
	cmd.Env = append(os.Environ(), fmt.Sprintf("REPO_NAME=%s", repoName))

	output, err := cmd.CombinedOutput()
	duration := time.Since(start)

	if err != nil {
		logger.Printf("Deploy failed for %s (took %v): %v\nOutput: %s", repoName, duration, err, output)
		return
	}

	logger.Printf("Deploy succeeded for %s (took %v)\nOutput: %s", repoName, duration, output)
}
