package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
)

func main() {
	port := flag.Int("port", 8888, "port to listen on")
	vuln := flag.Bool("vuln", true, "serve intentionally vulnerable pages")
	flag.Parse()

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "Apache/2.4.7 (Ubuntu)")
		w.Header().Set("X-Powered-By", "PHP/5.6.40")
		fmt.Fprintf(w, `<!DOCTYPE html><html><head><title>Vulnerable Test App</title></head><body>
<h1>Apophis test target</h1>
<form action="/login" method="POST">
<input name="q" value="%s">
<button>Search</button>
</form>
</body></html>`, r.URL.Query().Get("q"))
	})
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			fmt.Fprintln(w, "Invalid username or password.")
			return
		}
		fmt.Fprintln(w, "Login form")
	})
	mux.HandleFunc("/admin", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("WWW-Authenticate", `Basic realm="admin"`)
		w.WriteHeader(401)
	})
	mux.HandleFunc("/wp-login.php", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "WordPress login")
	})
	mux.HandleFunc("/.git/HEAD", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "ref: refs/heads/master")
	})
	mux.HandleFunc("/.env", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "DB_PASSWORD=hunter2")
	})

	if *vuln {
		mux.HandleFunc("/files/", func(w http.ResponseWriter, r *http.Request) {
			path := r.URL.Path[len("/files/"):]
			if path == "" {
				fmt.Fprintln(w, "file not found")
				return
			}
			fmt.Fprintf(w, "You requested: %s\n", path)
		})
		mux.HandleFunc("/search", func(w http.ResponseWriter, r *http.Request) {
			q := r.URL.Query().Get("q")
			w.Write([]byte("You searched for: " + q))
		})
	}

	addr := fmt.Sprintf(":%d", *port)
	log.Printf("test target listening on %s (vuln=%v)", addr, *vuln)
	if err := http.ListenAndServe(addr, mux); err != nil {
		log.Fatal(err)
	}
}
