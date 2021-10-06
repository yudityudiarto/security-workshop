package main

import (
	"log"
	"net/http"

	"github.com/ariefmaulidy/security-workshop/messaging"
	"github.com/nsqio/go-nsq"
)

var (
	producer messaging.Producer
	key      []byte
)

const (
	defaultConsumerMaxAttempts = 10
	defaultConsumerMaxInFlight = 100
)

type User struct {
	Name        string `json:"name"`
	Email       string `json:"email"`
	PhoneNumber string `json:"phone_number"`
	Age         int    `json:"age"`
}

type Item struct {
	Name       string `json:"name"`
	Price      int64  `json:"price"`
	Category   string `json:"category"`
	Quantity   int    `json:"quantity"`
	TotalPrice int64  `json:"total_price"`
}

type Payment struct {
	UserData     User   `json:"user_data"`
	ItemData     []Item `json:"item_data"`
	TotalPayment int64  `json:"total_payment"`
}

func main() {
	config := nsq.NewConfig()
	config.MaxAttempts = 200

	var err error
	producer, err = messaging.NewProducer(messaging.ProducerConfig{
		NsqdAddress: "172.18.59.254:4150",
	})
	if err != nil {
		log.Fatal("Failed init producer", err)
	}

	// initiate consumer
	consumer, err := messaging.NewConsumer(messaging.ConsumerConfig{
		Topic:         "test", // Change the topic
		Channel:       "test", // Change the channel
		LookupAddress: "172.18.59.254:4161",
		MaxAttempts:   defaultConsumerMaxAttempts,
		MaxInFlight:   defaultConsumerMaxInFlight,
		Handler:       handleMessage,
	})
	if err != nil {
		log.Fatal("Failed init consumer", err)
	}

	http.HandleFunc("/publish_payment", handlePublish)

	go messaging.RunConsumer(consumer)
	log.Fatal(http.ListenAndServe(":8090", nil))
}

func handlePublish(w http.ResponseWriter, r *http.Request) {
	// Do Publish
	topic := "" // TODO: update to given topic name
	msg := ""   // TODO: write your message here
	producer.Publish(topic, msg)
}

func handleMessage(message *nsq.Message) error {
	// Handle message NSQ here

	message.Finish()
	return nil
}
