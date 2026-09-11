use std::{collections::HashMap, str::FromStr, sync::Arc};

use dashmap::DashMap;

use skw_lib_shared::{
    APP, AppError,
    prelude::{
        chrono::*,
        consts::*,
        futures::StreamExt,
        iggy::*,
        jsonrpc::ServiceHttpError,
        log::{debug, error, info, warn},
        tools::*,
        uuid::Uuid,
    },
};

use tokio::sync::mpsc::UnboundedSender;

pub(crate) const CFG_BACK_TOPIC_PART_COUNT: &str = "/service/backTopicpartitionsCount";

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
        service_error: Option<ServiceHttpError>,
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
    service_error: Option<ServiceHttpError>,
    target_connection_id: Option<Uuid>,
}

impl TryFrom<ReceivedMessage> for WsBackMessage {
    type Error = String;

    fn try_from(m: ReceivedMessage) -> Result<Self, Self::Error> {
        let signature_key = HeaderKey::from_str(IGGY_HEADER_SIGNATURE).map_err(|e| e.to_string())?;
        let signature = m
            .message
            .get_user_header(&signature_key)
            .unwrap_or(None)
            .map(|s| s.to_string_value());

        let service_error_key = HeaderKey::from_str(IGGY_HEADER_SERVICE_ERROR).map_err(|e| e.to_string())?;
        let service_error = m
            .message
            .get_user_header(&service_error_key)
            .unwrap_or(None)
            .map(|s| s.to_string_value())
            .and_then(|v| v.parse::<ServiceHttpError>().ok());

        let target_key = HeaderKey::from_str(IGGY_HEADER_TARGET_WS_CONNECTION_ID).map_err(|e| e.to_string())?;
        let target_connection_id = m
            .message
            .get_user_header(&target_key)
            .unwrap_or(None)
            .map(|s| s.to_string_value())
            .and_then(|v| Uuid::parse_str(&v).ok());

        Ok(WsBackMessage {
            payload: m.message.payload.to_vec(),
            signature,
            service_error,
            target_connection_id,
        })
    }
}

impl WsGateState {
    pub(crate) async fn new(stream: &str, back_topic: &str, routes_map: RoutesMap, iggy_client: Arc<IggyClient>) -> Result<Self, AppError> {
        // gates/api joins a consumer group literally named "consumer-{back_topic}"
        // on this same shared back topic. Reusing that exact name here would put
        // both gates in the SAME Iggy consumer group, which splits partitions
        // between group members instead of giving each gate the full message
        // stream — replies meant for a gates/ws client could get delivered to
        // gates/api's consumer instead (and silently dropped there). Each gate
        // needs its own distinctly-named group so it independently sees every
        // back-topic message and filters locally.
        let consumer_name = format!("consumer-ws-{}", back_topic);

        let mut iggy_consumer = iggy_client
            .consumer_group(&consumer_name, stream, back_topic)
            .map_err(|e| AppError::Custom(e.to_string()))?
            .auto_commit(AutoCommit::When(AutoCommitWhen::ConsumingEachMessage))
            .create_consumer_group_if_not_exists()
            .auto_join_consumer_group()
            .polling_strategy(PollingStrategy::next())
            .poll_interval(IggyDuration::from_str("1ms").map_err(|e| AppError::Custom(e.to_string()))?)
            .batch_length(1)
            .build();

        iggy_consumer
            .init()
            .await
            .map_err(|e| AppError::Custom(e.to_string()))?;

        let pending_requests: Arc<DashMap<String, PendingRequestEntry>> = Arc::new(DashMap::with_capacity(1024));
        let connections: Arc<DashMap<Uuid, ConnectionEntry>> = Arc::new(DashMap::with_capacity(1024));

        let pr = pending_requests.clone();
        let conns = connections.clone();
        let consumer_name1 = consumer_name.clone();
        tokio::spawn(async move {
            loop {
                info!("starting ws-gate back receiver thread {}", consumer_name1);
                while let Some(message) = iggy_consumer.next().await {
                    match message {
                        Ok(received) => match WsBackMessage::try_from(received) {
                            Ok(m) => dispatch_back_message(&pr, &conns, m),
                            Err(e) => error!("error converting back message: {}", e),
                        },
                        Err(e) => error!("Error while receiving message: {}", e),
                    }
                }
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

/// looks up the reply's signature against the pending-request registry
/// (removing it — a request is answered at most once) and delivers directly
/// to that one connection's outbound channel; falls back to routing by
/// target-connection-id for unsolicited push messages that aren't replies to
/// any pending request. No fan-out: O(1) lookup instead of broadcasting to
/// every connection.
fn dispatch_back_message(pending: &DashMap<String, PendingRequestEntry>, connections: &DashMap<Uuid, ConnectionEntry>, m: WsBackMessage) {
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
            signature,
            payload: m.payload,
            service_error: m.service_error,
        });
        return;
    }

    if let Some(target) = &m.target_connection_id
        && let Some(entry) = connections.get(target)
    {
        let _ = entry.outbound.send(WsOutbound::Push { payload: m.payload });
    }
}

/// mirrors gates/api::init_iggy (main.rs:118-199): creates the shared stream,
/// the shared back topic, and one Iggy producer per service found in
/// /topicsMap, keyed by service name (the first path segment of a client's
/// WsRequest.uri, same convention gates/api uses for req.path()).
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
                let cfg: TopicConfig = topic_cfg.try_into()?;

                let topic = cfg
                    .custom_name
                    .unwrap_or(format!("{}-{}", service, VERSION));

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
                    .entry(service.clone())
                    .or_insert(Arc::new(producer));
            }
        }
        None => warn!("no topics configurations found in config"),
    }

    Ok(routes_map)
}

/// ws-adapted port of gates/api::send_message_to_service (main.rs:305-366).
/// IGGY_HEADER_HTTP_METHOD is set to a fixed "WS" marker since ws requests
/// have no HTTP method — libs/http-protos's TryInto<JsonRpcServiceRequest<T>>
/// requires this header to be present regardless of value.
pub(crate) async fn publish_to_service(
    producer: Arc<IggyProducer>,
    api_key: Option<&Uuid>,
    signature: &str,
    uri: &str,
    body: &[u8],
) -> Result<(), String> {
    let mut headers = std::collections::BTreeMap::new();

    headers.insert(
        HeaderKey::from_str(IGGY_HEADER_SIGNATURE).unwrap(),
        HeaderValue::from_str(signature).map_err(|e| e.to_string())?,
    );

    if let Some(key) = api_key {
        headers.insert(
            HeaderKey::from_str(IGGY_HEADER_API_KEY).unwrap(),
            HeaderValue::from_str(&key.to_string()).map_err(|e| e.to_string())?,
        );
    }

    headers.insert(
        HeaderKey::from_str(IGGY_HEADER_HTTP_METHOD).unwrap(),
        HeaderValue::from_str("WS").map_err(|e| e.to_string())?,
    );

    headers.insert(
        HeaderKey::from_str(IGGY_HEADER_HTTP_PATH).unwrap(),
        HeaderValue::from_str(uri).map_err(|e| e.to_string())?,
    );

    let bytes = Bytes::copy_from_slice(body);
    let message = IggyMessage::builder()
        .payload(bytes)
        .user_headers(headers)
        .build()
        .map_err(|e| e.to_string())?;

    producer
        .send_one(message)
        .await
        .map_err(|e| e.to_string())?;

    Ok(())
}
