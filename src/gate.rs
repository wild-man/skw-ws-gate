use std::{collections::HashMap, str::FromStr, sync::Arc};

use dashmap::DashMap;

use skw_lib_shared::{
    APP, AppError,
    prelude::{
        chrono::*,
        consts::*,
        futures::StreamExt,
        iggy::*,
        jsonrpc::{SkwServiceHttpError, SkwServiceStatus},
        log::{debug, error, info, warn},
        tools::*,
        uuid::Uuid,
    },
};

use tokio::sync::mpsc::UnboundedSender;

pub(crate) const CFG_BACK_TOPIC_PART_COUNT: &str = "/service/backTopicPartitionsCount";

/// pause between attempts to rebuild the back-topic consumer after its stream ended
const BACK_CONSUMER_RETRY_DELAY: std::time::Duration = std::time::Duration::from_secs(1);

#[derive(Clone)]
pub(crate) struct RoutesMap {
    pub map: HashMap<String, Arc<IggyProducer>>,
}

/// message handed from the shared back-topic consumer loop (or a request
/// dispatch's timeout watchdog) to a specific connection's heartbeat/writer
/// task, which is the only place allowed to touch that connection's WsSink
#[derive(Debug, Clone)]
pub(crate) enum WsOutbound {
    Reply {
        signature: String,
        payload: Vec<u8>,
        service_error: Option<SkwServiceHttpError>,
        /// Some = provisional reply (Created/Accepted): request taken, its result comes later
        service_status: Option<SkwServiceStatus>,
    },
    Push {
        payload: Vec<u8>,
    },
    Timeout {
        signature: String,
        uri: String,
    },
}

pub(crate) struct PendingRequestEntry {
    pub outbound: UnboundedSender<WsOutbound>,
    /// id echoed back to the client as the reply's `Signature`: the request signature for signed
    /// requests, the client-chosen request id for unsigned ones (whose registry key is minted by
    /// the gate, so ids picked by different clients can't collide)
    pub reply_id: String,
    pub uri: String,
    pub ts_gate_published: DateTime<Utc>,
}

pub(crate) struct ConnectionEntry {
    pub outbound: UnboundedSender<WsOutbound>,
}

#[derive(Clone)]
pub(crate) struct WsGateState {
    pub routes_map: RoutesMap,
    pub pending_requests: Arc<DashMap<String, PendingRequestEntry>>,
    pub connections: Arc<DashMap<Uuid, ConnectionEntry>>,
    pub _iggy_client: Arc<IggyClient>, // saved for future use if needed
}

/// parallel to gates/api's IggyReceivedMessage, plus an optional
/// target-connection-id for proactive/unsolicited push (consumption only —
/// no backend service produces this header yet)
#[derive(Debug, Clone)]
struct WsBackMessage {
    payload: Vec<u8>,
    signature: Option<String>,
    service_error: Option<SkwServiceHttpError>,
    service_status: Option<SkwServiceStatus>,
    target_connection_id: Option<Uuid>,
}

impl TryFrom<ReceivedMessage> for WsBackMessage {
    type Error = AppError;

    fn try_from(m: ReceivedMessage) -> Result<Self, Self::Error> {
        // decoded once: every `get_user_header` call would decode the whole map again
        let headers = m.message.user_headers_map()?;
        let header = |key: &HeaderKey| header_str(headers.as_ref(), key);

        Ok(WsBackMessage {
            signature: header(&header_keys::SIGNATURE),
            service_error: header(&header_keys::SERVICE_ERROR).and_then(|v| v.parse().ok()),
            service_status: header(&header_keys::SERVICE_STATUS).and_then(|v| v.parse().ok()),
            target_connection_id: header(&header_keys::TARGET_WS_CONNECTION_ID).and_then(|v| Uuid::parse_str(&v).ok()),
            payload: m.message.payload.to_vec(),
        })
    }
}

impl WsGateState {
    pub(crate) async fn new(stream: &str, back_topic: &str, routes_map: RoutesMap, iggy_client: Arc<IggyClient>) -> Result<Self, AppError> {
        // The group name is "consumer-{service name}-{back_topic}" (skw_get_consumer_name, service
        // name from /service/name, "skw-ws-gate"); gates/api uses its own service name on this
        // same shared back topic. A shared name would put
        // both gates in the SAME Iggy consumer group, which splits partitions
        // between group members instead of giving each gate the full message
        // stream — replies meant for a gates/ws client could get delivered to
        // gates/api's consumer instead (and silently dropped there). Each gate
        // needs its own distinctly-named group so it independently sees every
        // back-topic message and filters locally.
        //
        // Caveat: every ws-gate *process* uses this same group name, so running
        // several ws replicas puts them in one group and Iggy splits back
        // partitions between them — a reply for a request pending on replica A
        // can land on replica B, miss its `pending_requests`, get dropped, and A
        // times out. Before scaling horizontally, make the group per-instance or
        // route replies to a partition owned by the requesting instance.
        let consumer_name = skw_get_consumer_name(back_topic);

        // fail fast at startup; later failures are retried by the receiver loop below
        let mut iggy_consumer = build_back_consumer(&iggy_client, &consumer_name, stream, back_topic).await?;

        let pending_requests: Arc<DashMap<String, PendingRequestEntry>> = Arc::new(DashMap::with_capacity(1024));
        let connections: Arc<DashMap<Uuid, ConnectionEntry>> = Arc::new(DashMap::with_capacity(1024));

        let pr = pending_requests.clone();
        let conns = connections.clone();
        let client = iggy_client.clone();
        let stream = stream.to_string();
        let back_topic = back_topic.to_string();
        tokio::spawn(async move {
            loop {
                info!("starting ws-gate back receiver thread {}", consumer_name);
                while let Some(message) = iggy_consumer.next().await {
                    match message {
                        Ok(received) => match WsBackMessage::try_from(received) {
                            Ok(m) => dispatch_back_message(&pr, &conns, m),
                            Err(e) => error!("error converting back message: {}", e),
                        },
                        Err(e) => error!("Error while receiving message: {}", e),
                    }
                }

                // an ended stream stays ended: polling it again would spin without awaiting,
                // so rebuild the consumer (with a pause between attempts) and carry on
                warn!(
                    "ws-gate back receiver stream ended, rebuilding consumer {}",
                    consumer_name
                );
                iggy_consumer = loop {
                    tokio::time::sleep(BACK_CONSUMER_RETRY_DELAY).await;
                    match build_back_consumer(&client, &consumer_name, &stream, &back_topic).await {
                        Ok(c) => break c,
                        Err(e) => error!("rebuilding back consumer {} failed: {}", consumer_name, e),
                    }
                };
            }
        });

        Ok(Self {
            routes_map,
            pending_requests,
            connections,
            _iggy_client: iggy_client,
        })
    }
}

/// Joins (creating if needed) the back-topic consumer group and initializes the consumer.
async fn build_back_consumer(iggy_client: &IggyClient, consumer_name: &str, stream: &str, back_topic: &str) -> Result<IggyConsumer, AppError> {
    let mut iggy_consumer = iggy_client
        .consumer_group(consumer_name, stream, back_topic)?
        .auto_commit(AutoCommit::When(AutoCommitWhen::ConsumingEachMessage))
        .create_consumer_group_if_not_exists()
        .auto_join_consumer_group()
        .polling_strategy(PollingStrategy::next())
        .poll_interval(IggyDuration::from_str("1ms").map_err(|e| AppError::Custom(e.to_string()))?)
        .batch_length(1)
        .build();

    iggy_consumer.init().await?;
    Ok(iggy_consumer)
}

/// looks up the reply's signature against the pending-request registry
/// (removing it — a request is answered at most once) and delivers directly
/// to that one connection's outbound channel; falls back to routing by
/// target-connection-id for unsolicited push messages that aren't replies to
/// any pending request. No fan-out: O(1) lookup instead of broadcasting to
/// every connection.
fn dispatch_back_message(pending: &DashMap<String, PendingRequestEntry>, connections: &DashMap<Uuid, ConnectionEntry>, m: WsBackMessage) {
    // a provisional reply (Created/Accepted) is delivered but keeps the request pending:
    // its final reply comes later with the same signature (or the watchdog times it out)
    if m.service_status.is_some()
        && let Some(sig) = &m.signature
        && let Some(entry) = pending.get(sig)
    {
        debug!(
            "ws provisional reply delivered: signature={} uri={} status={:?} elapsed={:?}",
            sig,
            entry.uri,
            m.service_status,
            Utc::now() - entry.ts_gate_published
        );
        let _ = entry.outbound.send(WsOutbound::Reply {
            signature: entry.reply_id.clone(),
            payload: m.payload,
            service_error: m.service_error,
            service_status: m.service_status,
        });
        return;
    }

    // a final reply (or an error) ends the request
    if let Some(sig) = &m.signature
        && let Some((signature, entry)) = pending.remove(sig)
    {
        debug!(
            "ws reply delivered: signature={} uri={} elapsed={:?}",
            signature,
            entry.uri,
            Utc::now() - entry.ts_gate_published
        );
        let _ = entry.outbound.send(WsOutbound::Reply {
            signature: entry.reply_id,
            payload: m.payload,
            service_error: m.service_error,
            service_status: m.service_status,
        });
        return;
    }

    if let Some(target) = &m.target_connection_id
        && let Some(entry) = connections.get(target)
    {
        let _ = entry.outbound.send(WsOutbound::Push { payload: m.payload });
    }
}

pub(crate) async fn init_iggy(stream: &str, back_topic: &str, iggy_client: &IggyClient) -> Result<RoutesMap, AppError> {
    let stream_id = Identifier::from_str_value(stream).expect("invalid stream name");

    match iggy_client.create_stream(stream).await {
        Ok(sd) => info!("iggy stream {} created; id:{}", stream, sd.id),
        Err(e) => warn!("failed to create iggy stream {}: {}", stream, e),
    };
    let partitions_count = APP.config.expect_u32(CFG_BACK_TOPIC_PART_COUNT);

    match iggy_client
        .create_topic(
            &stream_id,
            back_topic,
            partitions_count,
            CompressionAlgorithm::None,
            None,
            IggyExpiry::ExpireDuration(IggyDuration::from_str("60s").unwrap()),
            MaxTopicSize::ServerDefault,
        )
        .await
    {
        Ok(tc) => info!("gate-back topic created: {:?}", tc),
        Err(e) => warn!("Error gate-back topic creation: {}", e),
    }

    let mut routes_map = RoutesMap {
        map: HashMap::with_capacity(100),
    };

    match APP.config.get(GATE_TOPICS_MAP) {
        Some(t) => {
            for (service, topic_cfg) in t.as_object().expect("invalid topic configuration").iter() {
                let cfg: TopicConfig = topic_cfg
                    .try_into()
                    .map_err(|e| format!("{GATE_TOPICS_MAP}/{service}: {e}"))?;
                for topic_type in &cfg.topic_types {
                    let topic = format!("{}-{}-{}", service, topic_type, VERSION);
                    let topic_key = format!("{service}/{topic_type}");

                    skw_is_valid_name(&topic).unwrap_or_else(|| panic!("invalid topic name: {}", topic));

                    match iggy_client
                        .create_topic(
                            &stream_id,
                            &topic,
                            cfg.partitions_count,
                            cfg.compression_algorithm,
                            None,
                            cfg.message_expiry,
                            cfg.max_topic_size,
                        )
                        .await
                    {
                        Ok(t) => info!("created topic: {} (id:{}); stream: {}", topic, t.id, stream),
                        Err(e) => warn!(
                            "error create topic: {}; stream: {}; error: {}",
                            topic, stream, e
                        ),
                    }

                    info!(
                        "creating producer for service: {}; stream: {}; topic: {};",
                        service, stream, topic
                    );

                    let producer = iggy_client
                        .producer(stream, &topic)
                        .expect("producer create error")
                        .partitioning(Partitioning::balanced())
                        .build();

                    routes_map
                        .map
                        .entry(topic_key)
                        .or_insert(Arc::new(producer));
                }
            }
        }
        None => warn!("no topics configurations found in config"),
    }

    Ok(routes_map)
}

pub(crate) async fn publish_to_service(
    producer: Arc<IggyProducer>,
    api_key: Option<&Uuid>,
    signature: &str,
    uri: &str,
    body: &[u8],
) -> Result<(), AppError> {
    let mut headers = std::collections::BTreeMap::new();

    headers.insert(
        header_keys::SIGNATURE.clone(),
        HeaderValue::from_str(signature)?,
    );

    if let Some(key) = api_key {
        headers.insert(
            header_keys::API_KEY.clone(),
            HeaderValue::from_str(&key.to_string())?,
        );
    }

    headers.insert(
        header_keys::HTTP_METHOD.clone(),
        HeaderValue::from_str("WS")?,
    );

    headers.insert(header_keys::HTTP_PATH.clone(), HeaderValue::from_str(uri)?);

    let bytes = Bytes::copy_from_slice(body);
    let message = IggyMessage::builder()
        .payload(bytes)
        .user_headers(headers)
        .build()?;

    producer.send_one(message).await?;

    Ok(())
}
