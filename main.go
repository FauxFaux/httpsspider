package main

import (
	"database/sql"
	"errors"
	"flag"
	"fmt"
	"log"
	"math/rand"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	sqlite3 "github.com/mattn/go-sqlite3"
	"github.com/mvdan/xurls"
	"golang.org/x/net/idna"
)

var dbLock sync.Mutex

func checkRedirect(req *http.Request, via []*http.Request) error {
	if len(via) >= 10 {
		return errors.New("stopped after 10 redirects")
	}

	if nil == req.URL || "https" != req.URL.Scheme {
		if len(via) > 0 {
			return http.ErrUseLastResponse
		}
		return errors.New("non-https redirect attempted")
	}
	return nil
}

func spiderName(name string) ([]string, error) {
	seen := make(map[string]bool)

	client := &http.Client{
		CheckRedirect: checkRedirect,
		Timeout:       time.Duration(5 * time.Second),
	}

	encoded, err := idna.ToASCII(name)
	if nil != err {
		return nil, err
	}

	resp, err := client.Get("https://" + encoded + "/")
	if nil != err {
		return nil, err
	}

	defer resp.Body.Close()

	chunk := make([]byte, 1024*1024)
	read, err := resp.Body.Read(chunk)
	chunk = chunk[:read]

	for _, bytes := range xurls.Strict.FindAll(chunk, -1) {
		full, err := url.Parse(string(bytes[:]))
		if nil != err || nil == full {
			continue
		}
		seen[full.Host] = true
	}

	if nil != resp.TLS && nil != resp.TLS.PeerCertificates {
		for _, cert := range resp.TLS.PeerCertificates {
			if nil != cert.DNSNames && len(cert.DNSNames) > 0 {
				for _, name := range cert.DNSNames {
					seen[name] = true
				}
			}
		}
	}

	ret := make([]string, 3)
	for name, _ := range seen {
		if strings.ContainsRune(name, ':') || !strings.ContainsRune(name, '.') {
			continue
		}
		ret = append(ret, name)
	}

	return ret, nil
}

func openDb() *sql.DB {
	db, err := sql.Open("sqlite3", "./state.db")
	if nil != err {
		log.Panic(err)
	}
	return db
}

func execOrPanic(db *sql.DB, sql string) {
	_, err := db.Exec(sql)
	if nil != err {
		log.Panic(err)
	}
}

func prepareOrPanic(db *sql.DB, sql string) *sql.Stmt {
	dbLock.Lock()
	stat, err := db.Prepare(sql)
	dbLock.Unlock()

	if nil != err {
		log.Panic(err)
	}
	return stat
}

func statExecOrPanic(stmt *sql.Stmt, args ...interface{}) {
	for i := 0; i < 5; i += 1 {
		dbLock.Lock()
		_, err := stmt.Exec(args...)
		dbLock.Unlock()

		if nil == err {
			return
		}

		sqlErr, ok := err.(sqlite3.Error)
		if !ok {
			log.Panic("unexpected error type: ", err)
		}

		if sqlErr.Code == sqlite3.ErrBusy {
			time.Sleep(time.Duration(rand.Intn(1 + (i * 200 * int(time.Millisecond)))))
			continue
		}

		if sqlErr.Code == sqlite3.ErrConstraint {
			// don't care about this case atm, and the extended error code checking is buggered
			return
		}

		log.Panic(err)
	}

	log.Panic("couldn't complete db query")
}

func main() {
	initCommand := flag.NewFlagSet("init", flag.ExitOnError)
	debugCommand := flag.NewFlagSet("debug", flag.ExitOnError)

	if len(os.Args) < 2 {
		fmt.Println("usage: <subcommand> [<args>]")
		fmt.Println("  init   Set up the database")
		fmt.Println("  debug  Run without touching the database")
		return
	}

	switch os.Args[1] {
	case "init":
		initCommand.Parse(os.Args[2:])
	case "debug":
		debugCommand.Parse(os.Args[2:])
	default:
		fmt.Printf("%q is not a valid subcommand.\n", os.Args[1])
		os.Exit(2)
	}

	if initCommand.Parsed() {
		db := openDb()
		defer db.Close()
		execOrPanic(db, `create table candidates (
			first_seen timestamp not null,
			hostname varchar not null primary key)`)
		execOrPanic(db, `create table access (
			instant timestamp not null,
			hostname varchar not null,
			error varchar)`)
		return
	}

	if debugCommand.Parsed() {
		db := openDb()
		defer db.Close()
		stCand := prepareOrPanic(db,
			`insert into candidates (first_seen, hostname) values (datetime('now'), ?)`)
		defer stCand.Close()

		stAccess := prepareOrPanic(db,
			`insert into access (instant, hostname, error) values (datetime('now'), ?, ?)`)
		defer stAccess.Close()

		var wg sync.WaitGroup
		for _, name := range debugCommand.Args() {
			wg.Add(1)
			go func(name string) {
				defer wg.Done()

				names, err := spiderName(name)
				if nil != err {
					statExecOrPanic(stAccess, name, err.Error())
					return
				} else {
					statExecOrPanic(stAccess, name, nil)
				}
				statExecOrPanic(stCand, name)
				for _, found := range names {
					statExecOrPanic(stCand, found)
				}
			}(name)
		}
		wg.Wait()
	}
}
