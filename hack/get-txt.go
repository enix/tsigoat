package main

import (
	"log"
	"os"

	"github.com/miekg/dns"
)

func main() {
	client := new(dns.Client)
	m := new(dns.Msg)

	m.SetQuestion(dns.Fqdn(os.Args[2]), dns.TypeTXT)

	r, _, err := client.Exchange(m, os.Args[1])
	if err != nil {
		log.Fatal(err)
	}

	for _, ans := range r.Answer {
		if txtRecord, ok := ans.(*dns.TXT); ok {
			log.Println(txtRecord.Txt)
		}
	}
}
