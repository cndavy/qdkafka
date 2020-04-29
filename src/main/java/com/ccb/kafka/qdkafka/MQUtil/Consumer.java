package com.ccb.kafka.qdkafka.MQUtil;


import org.apache.kafka.clients.consumer.ConsumerRecord;
import org.apache.kafka.clients.consumer.ConsumerRecords;
import org.apache.kafka.clients.consumer.KafkaConsumer;
import org.apache.kafka.common.serialization.StringDeserializer;


import java.util.Arrays;
import java.util.Properties;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * @author created by 旨酒思柔
 * @date 2019/3/27
 */
public class Consumer {
    static Logger log = Logger.getLogger(Consumer.class.getName());

    private static KafkaConsumer<String,String> consumer;

    /**
     *  初始化消费者
     */
    static {
        Properties configs = initConfig();
        consumer = new KafkaConsumer<String, String>(configs);
        consumer.subscribe(Arrays.asList(MQDict.CONSUMER_TOPIC));
    }
    /**
     *  初始化配置
     */
    private static Properties initConfig(){
        Properties props = new Properties();
        props.put("bootstrap.servers", MQDict.MQ_ADDRESS_COLLECTION);
        props.put("group.id", MQDict.CONSUMER_GROUP_ID);
        props.put("enable.auto.commit", MQDict.CONSUMER_ENABLE_AUTO_COMMIT);
        props.put("auto.commit.interval.ms", MQDict.CONSUMER_AUTO_COMMIT_INTERVAL_MS);
        props.put("session.timeout.ms", MQDict.CONSUMER_SESSION_TIMEOUT_MS);
        props.put("max.poll.records", MQDict.CONSUMER_MAX_POLL_RECORDS);
        props.put("auto.offset.reset", "earliest");
        props.put("key.deserializer", StringDeserializer.class.getName());
        props.put("value.deserializer", StringDeserializer.class.getName());
        return props;
    }

    public static void main(String[] args) {
       Logger.getLogger("org.apache.kafka").setLevel(Level.SEVERE);
        log.setLevel(Level.INFO);
        while (true) {

            ConsumerRecords<String, String> records = consumer.poll(MQDict.CONSUMER_POLL_TIME_OUT);
            records.forEach((ConsumerRecord<String, String> record)->{
                log.info("revice: key ==="+record.key()+" value ===="+record.value()+" topic ==="+record.topic());
            });
        }
    }

}

