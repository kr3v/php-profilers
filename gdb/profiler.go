package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"path"
	"strconv"
	"strings"
	"syscall"
	"time"

	"php-gdb/gdb"
)

///

func collectCStack(g *gdb.Gdb) ([]string, error) {
	send, err := g.Send("stack-list-frames")
	if err != nil {
		return nil, err
	}
	var stackM []string
	stack, ok := send["payload"].(map[string]interface{})["stack"].([]interface{})
	if !ok {
		return nil, fmt.Errorf("stack not found?: %v", send)
	}
	for _, f := range stack {
		stackM = append(stackM, f.(map[string]interface{})["frame"].(map[string]interface{})["func"].(string))
	}
	return stackM, nil
}

///

func phpStackAt(depth int) string {
	cmd := "executor_globals->current_execute_data->"
	for i := 0; i < depth; i++ {
		cmd += "prev_execute_data->"
	}
	return strings.TrimSuffix(cmd, "->")
}

func CollectPHPStack(g *gdb.Gdb) (s []string, e error) {
	send, err := g.Send("data-evaluate-expression", phpStackAt(0)+"->prev_execute_data")
	if err != nil {
		return nil, err
	}
	val, ok := send["payload"].(map[string]interface{})["value"].(string)
	if !ok {
		return nil, fmt.Errorf("value not found?: %v", send)
	}
	for i := 0; val != "" && val != "0" && val != "0x0"; i++ {
		send, err := g.Send("data-evaluate-expression", "(char*)"+phpStackAt(i)+"->func->common->function_name->val")
		if err != nil {
			return s, err
		}
		if s1, ok := send["payload"].(map[string]interface{})["value"].(string); ok {
			s = append(s, s1)
		} else {
			s = append(s, "<unknown>")
		}

		send, err = g.Send("data-evaluate-expression", phpStackAt(i)+"->prev_execute_data")
		if err != nil {
			return s, err
		}
		val = send["payload"].(map[string]interface{})["value"].(string)
	}
	return s, nil
}

///

type Stack struct {
	PHP []string
	C   []string
}

///

const (
	interpreter = "/usr/bin/php"
	testScript  = "/root/tmp/a.php"
	defaultRate = 17
)

func script(g *gdb.Gdb, s string, a []string) error {
	send, err := g.Send("file-exec-and-symbols", interpreter)
	if err != nil {
		return err
	}
	log.Println(send)
	send, err = g.Send("exec-arguments", append([]string{s}, a...)...)
	if err != nil {
		return err
	}
	log.Println(send)
	send, err = g.Send("exec-run")
	if err != nil {
		return err
	}
	log.Println(send)
	return nil
}

func attach(g *gdb.Gdb, pid int) error {
	send, err := g.Send("target-attach", strconv.Itoa(pid))
	if err != nil {
		return err
	}
	log.Println(send)
	if _, err := g.Send("exec-continue"); err != nil {
		return err
	}
	log.Println(send)
	return nil
}

type args struct {
	script string
	pid    int
	rate   int
	output string

	args []string
}

func parseArgs() (a args) {
	flag.StringVar(&a.script, "script", testScript, "wrap script execution")
	flag.IntVar(&a.pid, "pid", 0, "attach to pid")
	flag.IntVar(&a.rate, "rate", defaultRate, "collection rate in hz")
	wd, _ := os.Getwd()
	flag.StringVar(&a.output, "output", path.Join(wd, "stack."+strconv.FormatInt(time.Now().Unix(), 10)+".json"), "output path")
	flag.Parse()
	a.args = flag.Args()
	return
}

///

func main() {
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)

	log.SetFlags(log.Flags() | log.Lmicroseconds | log.Lshortfile)

	stopped1 := make(chan struct{}, 1)
	stopped2 := make(chan struct{}, 1)

	var g *gdb.Gdb

	notifications := make(chan map[string]interface{}, 64)
	// start a new instance and pipe the target output to stdout
	handler := func(notification map[string]interface{}) {
		notifications <- notification
	}
	go func() {
		for notification := range notifications {
			if v, ok := notification["class"].(string); ok && v == "thread-group-exited" {
				select {
				case <-sigs:
					break
				default:
					close(sigs)
				}
			}
			if v, ok := notification["class"].(string); ok && v == "stopped" {
				select {
				case stopped1 <- struct{}{}:
					break
				case <-stopped2:
				default:
				}
			}
			log.Println(notification)
		}
	}()

	g, _ = gdb.New(handler)
	go func() {
		_, err := io.Copy(os.Stdout, g)
		if err != nil {
			log.Println("io.Copy:", err)
		}
	}()

	a := parseArgs()
	f, err := os.Create(a.output)
	if err != nil {
		log.Fatalln(err)
	}
	defer f.Close()
	o := json.NewEncoder(f)
	if a.pid > 0 {
		log.Println("attaching to", a.pid, "pid")
		if err := attach(g, a.pid); err != nil {
			log.Fatalln(err)
		}
	} else {
		log.Println("executing script", a.script, "with args", a.args)
		if err := script(g, a.script, a.args); err != nil {
			log.Fatalln(err)
		}
	}

	dur := 1 * time.Second / time.Duration(a.rate)
	log.Println(dur)
	t := time.NewTicker(dur)
	defer t.Stop()

	time.Sleep(10 * time.Second)

	now1 := time.Now()
	i := 0
	defer func() {
		now2 := time.Now()
		log.Println("profiler run for", now2.Sub(now1), "and collected", i, "stacks", "(it was expected to collect", int(now2.Sub(now1)/dur), "stacks)")
	}()

For:
	for {
		select {
		case <-t.C:
			n1 := time.Now()
			if err := g.Interrupt(); err != nil {
				log.Println(err)
				break For
			}
			<-stopped1
			time.Sleep(5 * time.Millisecond)

			var a Stack
			var err error

			log.Println("C...")
			a.C, err = collectCStack(g)
			if err != nil {
				log.Println("collectCStack", err)
			}
			log.Println("...C")

			log.Println("PHP...")
			a.PHP, err = CollectPHPStack(g)
			if err != nil {
				log.Println("CollectPHPStack", err)
			}
			log.Println("...PHP")

			if err := o.Encode(a); err != nil {
				log.Println("stdout encode", a, err)
			}
			i++

			if _, err := g.Send("exec-continue"); err != nil {
				log.Println(err)
				break For
			}
			n2 := time.Now()

			time.Sleep(n2.Sub(n1))
		case sig := <-sigs:
			log.Println("signal", sig)
			break For
		}
	}
	close(stopped2)

	if err := g.Exit(); err != nil {
		log.Fatalln(err)
	}
}
