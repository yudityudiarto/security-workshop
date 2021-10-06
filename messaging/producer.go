package messaging

import (
	"encoding/json"

	"github.com/nsqio/go-nsq"
)

const (
	defaultNSQPrefix = "bgp_tech_cur_"
)

type (
	ProducerConfig struct {
		NsqdAddress string
	}

	Producer struct {
		prod *nsq.Producer
	}
)

func NewProducer(cfg ProducerConfig) (prod Producer, err error) {
	p, err := nsq.NewProducer(cfg.NsqdAddress, nsq.NewConfig())
	if err != nil {
		return prod, err
	}

	return Producer{
		prod: p,
	}, nil
}

func (p *Producer) Publish(topic string, msg interface{}) error {
	payload, err := json.Marshal(msg)
	if err != nil {
		return err
	}
	topic = defaultNSQPrefix + topic

	return p.prod.Publish(topic, payload)
}
