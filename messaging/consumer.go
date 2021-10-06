package messaging

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/nsqio/go-nsq"
)

type (
	ConsumerConfig struct {
		Topic         string
		Channel       string
		LookupAddress string
		MaxAttempts   uint16
		MaxInFlight   int
		Handler       nsq.HandlerFunc
	}

	Consumer struct {
		cons          *nsq.Consumer
		lookupAddress string
		handler       nsq.HandlerFunc
	}
)

func NewConsumer(cfg ConsumerConfig) (cons Consumer, err error) {
	nsqConf := nsq.NewConfig()
	nsqConf.MaxAttempts = cfg.MaxAttempts
	nsqConf.MaxInFlight = cfg.MaxInFlight

	topic := defaultNSQPrefix + cfg.Topic
	c, err := nsq.NewConsumer(topic, cfg.Channel, nsq.NewConfig())
	if err != nil {
		return cons, err
	}
	return Consumer{
		cons:          c,
		lookupAddress: cfg.LookupAddress,
		handler:       cfg.Handler,
	}, nil
}

func (c *Consumer) Run() {
	c.cons.AddHandler(c.handler)
	err := c.cons.ConnectToNSQLookupd(c.lookupAddress)
	if err != nil {
		log.Fatal(err)
	}
}

func RunConsumer(c Consumer) {
	// run consumer
	c.Run()

	fmt.Println("NSQ Running")

	// keep app alive until terminated
	term := make(chan os.Signal, 1)
	signal.Notify(term, os.Interrupt, syscall.SIGTERM, syscall.SIGHUP)
	select {
	case <-term:
		log.Println("Application terminated")
	}
}
